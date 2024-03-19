import asyncio
import json
import logging
import os
import re
import sys
import traceback
import requests
import aiohttp
import click
import tarfile
import hashlib
import shutil
from collections import OrderedDict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Union
from urllib.parse import quote
from ruamel.yaml import YAML
from semver import VersionInfo
from tenacity import (RetryCallState, RetryError, retry,
                      retry_if_exception_type, retry_if_result,
                      stop_after_attempt, wait_fixed)

from artcommonlib.arch_util import brew_suffix_for_arch, brew_arch_for_go_arch, \
    go_suffix_for_arch, go_arch_for_brew_arch
from artcommonlib.rhcos import get_primary_container_name
from doozerlib import assembly
from pyartcd.locks import Lock
from pyartcd.signatory import AsyncSignatory
from pyartcd.util import nightlies_with_pullspecs
from pyartcd import constants, exectools, locks, util, jenkins
from pyartcd.cli import cli, click_coroutine, pass_runtime
from artcommonlib.exceptions import VerificationError
from pyartcd.jira import JIRAClient
from pyartcd.mail import MailService
from pyartcd.s3 import sync_dir_to_s3_mirror
from pyartcd.oc import get_release_image_info, get_release_image_pullspec, extract_release_binary, \
    extract_release_client_tools, get_release_image_info_from_pullspec, extract_baremetal_installer
from pyartcd.runtime import Runtime, GroupRuntime


yaml = YAML(typ="safe")
yaml.default_flow_style = False


class CosignPipeline:
    DEST_RELEASE_IMAGE_REPO = constants.RELEASE_IMAGE_REPO

    @classmethod
    async def create(cls, *args, **kwargs):
        self = cls(*args, **kwargs)
        self.group_runtime = await GroupRuntime.create(
            self.runtime.config, self.runtime.working_dir,
            self.group, self.assembly
        )
        return self

    def __init__(self, runtime: Runtime, group: str, assembly: str,
                 multi: str,
                 signing_key: str,
                 pullspecs: Optional[List[str]]
                ) -> None:
        self.runtime = runtime
        self.group = group
        self.assembly = assembly
        self.sign_multi = multi != "no"
        self.sign_arches = multi != "only"
        self.signing_key = signing_key

        self._logger = self.runtime.logger

        self._working_dir = self.runtime.working_dir
        self._doozer_working_dir = self._working_dir / "doozer-working"
        self._doozer_env_vars = os.environ.copy()
        self._doozer_env_vars["DOOZER_WORKING_DIR"] = str(self._doozer_working_dir)

    def check_environment_variables(self):
        logger = self.runtime.logger

        required_vars = ["QUAY_USERNAME", "QUAY_PASSWORD"]
        required_vars.append("KMS_CRED_FILE" if self.signing_key == "prod" else "TEST_KMS_CRED_FILE")

        for env_var in required_vars:
            if not os.environ.get(env_var):  # not there, or empty
                msg = f"Environment variable {env_var} is not set."
                if self.runtime.dry_run:
                    logger.warning(msg)
                else:
                    raise ValueError(msg)

    async def login_quay(self):
        # the login command has only the variable names in it, so the values can be picked up from
        # the environment rather than on the command line where they would be logged.
        # better would be to have jenkins write a credentials file and do the same with `promote`.
        cmd = f'podman login -u "$QUAY_USERNAME" -p "$QUAY_PASSWORD" quay.io'
        await exectools.cmd_assert_async(['bash', '-c', cmd], env=os.environ.copy(), stdout=sys.stderr)


    async def run(self):
        logger = self.runtime.logger
        self.check_environment_variables()
        # await self.login_quay()

        # Load group config and releases.yml
        logger.info("Loading build data...")
        group_config = self.group_runtime.group_config
        releases_config = await util.load_releases_config(
            group=self.group,
            data_path=self._doozer_env_vars.get("DOOZER_DATA_PATH", None) or constants.OCP_BUILD_DATA_URL
        )
        if releases_config.get("releases", {}).get(self.assembly) is None:
            raise ValueError(f"To sign this release, assembly {self.assembly} must be explicitly defined in releases.yml.")

        # Get release name
        assembly_type = util.get_assembly_type(releases_config, self.assembly)
        release_name = util.get_release_name_for_assembly(self.group, releases_config, self.assembly)
        # Ensure release name is valid
        if not VersionInfo.is_valid(release_name):
            raise ValueError(f"Release name `{release_name}` is not a valid semver.")
        logger.info("Release name: %s", release_name)

        justifications = []
        try:
            if self.sign_multi and not group_config.get("multi_arch", {}).get("enabled", False)
                raise ValueError("Can't sign a multi payload: multi_arch.enabled is not set in group config")
            # Get arches
            arches = group_config.get("arches", [])
            arches = list(set(map(brew_arch_for_go_arch, arches)))
            if not arches:
                raise ValueError("No arches specified in group config.")

            # Promote release images
            metadata = {}
            release_infos = await self.promote(assembly_type, release_name, arches, previous_list, metadata, reference_releases, tag_stable)
            pullspecs = {arch: release_info["image"] for arch, release_info in release_infos.items()}
            pullspecs_repr = ", ".join(f"{arch}: {pullspecs[arch]}" for arch in sorted(pullspecs.keys()))

                    await locks.run_with_lock(
                        coro=self.sign_artifacts(release_name, client_type, release_infos, message_digests),
                        lock=lock,
                        lock_name=lock.value.format(signing_env=self.signing_env),
                        lock_id=lock_identifier
                    )

        except Exception as err:
            self._logger.exception(err)
            error_message = f"Error promoting release {release_name}: {err}\n {traceback.format_exc()}"
            message = f"Promoting release {release_name} failed with: {error_message}"
            await self._slack_client.say_in_thread(message)
            raise

        # Print release infos to console
        data = {
            "group": self.group,
            "assembly": self.assembly,
            "type": assembly_type.value,
            "name": release_name,
            "content": {},
            "justifications": justifications,
        }
        if image_advisory > 0:
            data["advisory"] = image_advisory
        if errata_url:
            data["live_url"] = errata_url
        for arch, release_info in release_infos.items():
            data["content"][arch] = {
                "pullspec": release_info["image"],
                "digest": release_info["digest"],
                "metadata": {k: release_info["metadata"][k] for k in release_info["metadata"].keys() & {'version', 'previous'}},
            }
            # if this payload is a manifest list, iterate through each manifest
            manifests = release_info.get("manifests", [])
            if manifests:
                manifests_ent = data["content"][arch]["manifests"] = {}
                for manifest in manifests:
                    if manifest["platform"]["os"] != "linux":
                        logger.warning("Unsupported OS %s in manifest list %s", manifest["platform"]["os"], release_info["image"])
                        continue
                    manifest_arch = brew_arch_for_go_arch(manifest["platform"]["architecture"])
                    manifests_ent[manifest_arch] = {
                        "digest": manifest["digest"]
                    }

            from_release = release_info.get("references", {}).get("metadata", {}).get("annotations", {}).get("release.openshift.io/from-release")
            if from_release:
                data["content"][arch]["from_release"] = from_release
            rhcos_version = release_info.get("displayVersions", {}).get("machine-os", {}).get("Version", "")
            if rhcos_version:
                data["content"][arch]["rhcos_version"] = rhcos_version

        json.dump(data, sys.stdout)


    async def sign_artifacts(self, release_name: str, client_type: str, release_infos: Dict, message_digests: List[str]):
        """ Signs artifacts and publishes signature files to mirror
        """
        if not self.signing_env:
            raise ValueError("--signing-env is missing")
        cert_file = os.environ["SIGNING_CERT"]
        key_file = os.environ["SIGNING_KEY"]
        uri = constants.UMB_BROKERS[self.signing_env]
        sig_keyname = "redhatrelease2" if client_type == 'ocp' else "beta2"
        self._logger.info("About to sign artifacts with key %s", sig_keyname)
        json_digest_sig_dir = self._working_dir / "json_digests"
        message_digest_sig_dir = self._working_dir / "message_digests"
        base_to_mirror_dir = self._working_dir / "to_mirror/openshift-v4"

        async with AsyncSignatory(uri, cert_file, key_file, sig_keyname=sig_keyname) as signatory:
            tasks = []
            json_digests = []
            for release_info in release_infos.values():
                version = release_info["metadata"]["version"]
                pullspec = release_info["image"]
                digest = release_info["digest"]
                json_digests.append((version, pullspec, digest))
                # if this payload is a manifest list, iterate through each manifest
                manifests = release_info.get("manifests", [])
                for manifest in manifests:
                    if manifest["platform"]["os"] != "linux":
                        raise ValueError("Unsupported OS %s in manifest list %s", manifest["platform"]["os"], release_info["image"])
                    json_digests.append((version, pullspec, manifest["digest"]))

            for version, pullspec, digest in json_digests:
                sig_file = json_digest_sig_dir / f"{digest.replace(':', '=')}" / "signature-1"
                tasks.append(self._sign_json_digest(signatory, version, pullspec, digest, sig_file))

            for message_digest in message_digests:
                input_path = base_to_mirror_dir / message_digest
                if not input_path.is_file():
                    raise IOError(f"Message digest file {input_path} doesn't exist or is not a regular file")
                sig_file = message_digest_sig_dir / f"{message_digest}.gpg"
                tasks.append(self._sign_message_digest(signatory, release_name, input_path, sig_file))
            await asyncio.gather(*tasks)

        self._logger.info("All artifacts have been successfully signed.")
        self._logger.info("Publishing signatures...")
        tasks = []
        if json_digests:
            tasks.append(self._publish_json_digest_signatures(json_digest_sig_dir))
        if message_digests:
            tasks.append(self._publish_message_digest_signatures(message_digest_sig_dir))
        await asyncio.gather(*tasks)
        self._logger.info("All signatures have been published.")

    async def _sign_json_digest(self, signatory: AsyncSignatory, release_name: str, pullspec: str, digest: str, sig_path: Path):
        """ Sign a JSON digest claim
        :param signatory: Signatory
        :param pullspec: Pullspec of the payload
        :param digest: SHA256 digest of the payload
        :param sig_path: Where to save the signature file
        """
        self._logger.info("Signing json digest for payload %s with digest %s...", pullspec, digest)
        if self.runtime.dry_run:
            self._logger.warning("[DRY RUN] Would have signed the requested artifact.")
            return
        sig_path.parent.mkdir(parents=True, exist_ok=True)
        with open(sig_path, "wb") as sig_file:
            await signatory.sign_json_digest(
                product="openshift",
                release_name=release_name,
                pullspec=pullspec,
                digest=digest,
                sig_file=sig_file)



    async def promote(self, assembly_type: assembly.AssemblyTypes, release_name: str, arches: List[str], previous_list: List[str], metadata: Optional[Dict], reference_releases: Dict[str, str], tag_stable: bool):
        """ Promote all release payloads
        :param assembly_type: Assembly type
        :param release_name: Release name. e.g. 4.11.0-rc.6
        :param arches: List of architecture names. e.g. ["x86_64", "s390x"]. Don't use "multi" in this parameter.
        :param previous_list: Previous list.
        :param metadata: Payload metadata
        :param reference_releases: A dict of reference release payloads to promote. Keys are architecture names, values are payload pullspecs
        :param tag_stable: Whether to tag the promoted payload to "4-stable[-$arch]" release stream.
        :return: A dict. Keys are architecture name or "multi", values are release_info dicts.
        """
        tasks = OrderedDict()
        if not self.no_multi and self._multi_enabled:
            tasks["heterogeneous"] = self._promote_heterogeneous_payload(assembly_type, release_name, arches, previous_list, metadata, tag_stable)
        else:
            self._logger.warning("Multi/heterogeneous payload is disabled.")
        if not self.multi_only:
            tasks["homogeneous"] = self._promote_homogeneous_payloads(assembly_type, release_name, arches, previous_list, metadata, reference_releases, tag_stable)
        else:
            self._logger.warning("Arch-specific homogeneous release payloads will not be promoted because --multi-only is set.")
        try:
            results = dict(zip(tasks.keys(), await asyncio.gather(*tasks.values())))
        except ChildProcessError as err:
            self._logger.error("Error promoting release images: %s\n%s", str(err), traceback.format_exc())
            raise
        return_value = {}
        if "homogeneous" in results:
            return_value.update(results["homogeneous"])
        if "heterogeneous" in results:
            return_value["multi"] = results["heterogeneous"]
        return return_value

    async def _promote_homogeneous_payloads(self, assembly_type: assembly.AssemblyTypes, release_name: str, arches: List[str], previous_list: List[str], metadata: Optional[Dict], reference_releases: Dict[str, str], tag_stable: bool):
        """ Promote homogeneous payloads for specified architectures
        :param assembly_type: Assembly type
        :param release_name: Release name. e.g. 4.11.0-rc.6
        :param arches: List of architecture names. e.g. ["x86_64", "s390x"].
        :param previous_list: Previous list.
        :param metadata: Payload metadata
        :param reference_releases: A dict of reference release payloads to promote. Keys are architecture names, values are payload pullspecs
        :param tag_stable: Whether to tag the promoted payload to "4-stable[-$arch]" release stream.
        :return: A dict. Keys are architecture name, values are release_info dicts.
        """
        tasks = []
        for arch in arches:
            tasks.append(self._promote_arch(assembly_type, release_name, arch, previous_list, metadata, reference_releases.get(arch), tag_stable))
        release_infos = await asyncio.gather(*tasks)
        return dict(zip(arches, release_infos))


    @staticmethod
    async def get_image_info(pullspec: str, raise_if_not_found: bool = False):
        # Get image manifest/manifest-list.
        cmd = f'oc image info --show-multiarch -o json {pullspec}'
        env = os.environ.copy()
        rc, stdout, stderr = await exectools.cmd_gather_async(cmd, check=False, env=env)
        if rc != 0:
            if "not found: manifest unknown" in stderr or "was deleted or has expired" in stderr:
                # image doesn't exist
                if raise_if_not_found:
                    raise IOError(f"Image {pullspec} is not found.")
                return None
            raise ChildProcessError(f"Error running {cmd}: exit_code={rc}, stdout={stdout}, stderr={stderr}")

        # Info provided by oc need to be converted back into Skopeo-looking format
        info = json.loads(stdout)
        if not isinstance(info, list):
            raise ValueError(f"Invalid image info: {info}")

        media_types = set([manifest['mediaType'] for manifest in info])
        if len(media_types) > 1:
            raise ValueError(f'Inconsistent media types across manifests: {media_types}')

        manifests = {
            'mediaType': "application/vnd.docker.distribution.manifest.list.v2+json",
            'manifests': [
                {
                    'digest': manifest['digest'],
                    'platform': {
                        'architecture': manifest['config']['architecture'],
                        'os': manifest['config']['os']
                    }
                } for manifest in info
            ]
        }

        return manifests

    @staticmethod
    async def get_multi_image_digest(pullspec: str, raise_if_not_found: bool = False):
        # Get image digest
        cmd = f'oc image info {pullspec} --filter-by-os linux/amd64 -o json'
        env = os.environ.copy()
        rc, stdout, stderr = await exectools.cmd_gather_async(cmd, check=False, env=env)

        if rc != 0:
            if "manifest unknown" in stderr or "was deleted or has expired" in stderr:
                # image doesn't exist
                if raise_if_not_found:
                    raise IOError(f"Image {pullspec} is not found.")
                return None
            raise ChildProcessError(f"Error running {cmd}: exit_code={rc}, stdout={stdout}, stderr={stderr}")

        return json.loads(stdout)['listDigest']

    @staticmethod
    async def get_image_stream_tag(namespace: str, image_stream_tag: str):
        cmd = [
            "oc",
            "-n",
            namespace,
            "get",
            "imagestreamtag",
            "-o",
            "json",
            "--ignore-not-found",
            "--",
            image_stream_tag,
        ]
        env = os.environ.copy()
        env["GOTRACEBACK"] = "all"
        _, stdout, _ = await exectools.cmd_gather_async(cmd, env=env, stderr=None)
        stdout = stdout.strip()
        if not stdout:  # Not found
            return None
        return json.loads(stdout)


@cli.command("cosign-container")
@click.option("-g", "--group", metavar='NAME', required=True,
              help="The group of components on which to operate. e.g. openshift-4.15")
@click.option("--assembly", metavar="ASSEMBLY_NAME", required=True,
              help="The name of an assembly to be signed. e.g. 4.15.1")
@click.option("--multi", type=click.Choice(("yes", "no", "only")), help="Whether to sign multi-arch or arch-specific payloads.")
@click.option("--signing-key", type=click.Choice(("prod", "stage")),
              help="Key to use for signing: prod or stage")
@click.argument('pullspecs', nargs=-1, required=False)
@pass_runtime
@click_coroutine
async def cosign_container(runtime: Runtime, group: str, assembly: str,
                  multi: Optional[str]="yes",
                  signing_key: Optional[str]="prod",
                  pullspecs: Optional[List[str]]=None):
    pipeline = await CosignPipeline.create(
        runtime, group, assembly,
        multi, signing_key, pullspecs
    )
    await pipeline.run()
