import asyncio
import json
import os
import sys
import click
from typing import Dict, Iterable, List, Optional, Union
from semver import VersionInfo

from pyartcd.signatory import AsyncSignatory
from pyartcd import constants, exectools, util
from pyartcd.cli import cli, click_coroutine, pass_runtime
from pyartcd.oc import get_release_image_info, get_image_info
from pyartcd.runtime import Runtime, GroupRuntime


class SigstorePipeline:

    @classmethod
    async def create(cls, *args, **kwargs):
        self = cls(*args, **kwargs)
        self.group_runtime = await GroupRuntime.create(
            self.runtime.config, self.runtime.working_dir,
            self.group, self.assembly
        )
        return self

    def __init__(self, runtime: Runtime, group: str, assembly: str,
                 multi: str, signing_key: str,
                 pullspecs: Optional[List[str]]
                ) -> None:
        self.runtime = runtime
        self.group = group
        self.assembly = assembly
        self.sign_multi = multi != "no"
        self.sign_arches = multi != "only"
        self.signing_key = signing_key
        self.pullspecs = pullspecs

        if signing_key == "prod":
            self.signing_creds = os.environ.get("KMS_CRED_FILE", "dummy-file")
            self.signing_key_id = os.environ.get("KMS_KEY_ID", "dummy-key")
        else:
            self.signing_creds = os.environ.get("TEST_KMS_CRED_FILE", "dummy-file")
            self.signing_key_id = os.environ.get("TEST_KMS_KEY_ID", "dummy-key")

        self._logger = self.runtime.logger

        self._working_dir = self.runtime.working_dir
        self._doozer_working_dir = self._working_dir / "doozer-working"
        self._doozer_env_vars = os.environ.copy()
        self._doozer_env_vars["DOOZER_WORKING_DIR"] = str(self._doozer_working_dir)

    def check_environment_variables(self):
        logger = self.runtime.logger

        required_vars = ["QUAY_USERNAME", "QUAY_PASSWORD"]
        if self.signing_key == "prod":
            required_vars += ["KMS_CRED_FILE", "KMS_KEY_ID"]
        else:
            required_vars += ["TEST_KMS_CRED_FILE", "TEST_KMS_KEY_ID"]

        for env_var in required_vars:
            if not os.environ.get(env_var):  # not there, or empty
                msg = f"Environment variable {env_var} is not set."
                if self.runtime.dry_run:
                    logger.warning(msg)
                else:
                    raise ValueError(msg)

    async def login_quay(self):
        # the login command has only the variable names in it, so the values can be picked up from
        # the environment rather than included in the command line where they would be logged.
        # better would be to have jenkins write a credentials file (and do the same in `promote`).
        return  # XXX
        cmd = f'podman login -u "$QUAY_USERNAME" -p "$QUAY_PASSWORD" quay.io'
        await exectools.cmd_assert_async(['bash', '-c', cmd], env=os.environ.copy(), stdout=sys.stderr)

    async def run(self):
        logger = self.runtime.logger
        self.check_environment_variables()
        await self.login_quay()

        # Load group config and releases.yml
        logger.info("Loading build metadata...")
        group_config = self.group_runtime.group_config
        releases_config = await util.load_releases_config(
            group=self.group,
            data_path=self._doozer_env_vars.get("DOOZER_DATA_PATH") or constants.OCP_BUILD_DATA_URL
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

        if not self.pullspecs:
            # look up release images we expect to be there since none given
            arches = releases_config.get("group", {}).get("arches") or group_config.get("arches") or []
            if self.sign_multi:
                arches.append("multi")
            self.pullspecs = list(f"{constants.RELEASE_IMAGE_REPO}:{release_name}-{arch}" for arch in arches)

        # sign these serially for now... minimize confusion if something goes wrong
        if not all([await self.sign_pullspec(ps, release_name) for ps in self.pullspecs]):
            raise RuntimeError("Not all succeeded, check errors above.")

    @staticmethod
    def _digestify_pullspec(pullspec, digest):
        """ given an existing pullspec, give the pullspec for a digest in the same repo """
        if len(halves := pullspec.split("@sha256:")) == 2:  # assume that was a digest at the end
            return f"{halves[0]}@{digest}"
        elif len(halves := pullspec.rsplit(":", 1)) == 2:
            # assume that was a tag at the end, while allowing for ":" in the registry spec
            return f"{halves[0]}@{digest}"
        return f"{pullspec}@{digest}"  # assume it was a bare registry/repo

    async def sign_pullspec(self, pullspec: str, release_name: Optional[str] = None) -> bool:
        """
        determine what a pullspec is (single manifest, manifest list, release image) and
        recursively sign it or its references.
        :param pullspec: Pullspec to be signed
        :param release_name: Require any release images to have this release name
        """
        self._logger.info("Preparing to sign %s", pullspec)
        img_info = await get_image_info(pullspec, True)
        tasks = []
        if isinstance(img_info, list):  # pullspec is for a manifest list
            tasks = [
                self.sign_pullspec(
                    self._digestify_pullspec(manifest["name"], manifest["digest"]),
                    release_name)
                for manifest in img_info
            ]
        elif (this_rn := img_info["config"]["config"]["Labels"].get("io.openshift.release")):
            # get references and sign those
            if release_name and release_name != this_rn:
                self._logger.error(
                    "release image at %s has release name %s, not the expected %s",
                    pullspec, this_rn, release_name)
                return False
            tasks = [
                self.sign_pullspec(ps)
                for ps in await self.get_release_image_references(pullspec)
            ]
            # also sign the release image
            tasks.append(self._sign_single_manifest(pullspec))
        else:  # pullspec is for a normal image manifest
            tasks.append(self._sign_single_manifest(pullspec))

        return all(await asyncio.gather(*tasks))  # true if all succeed

    async def _sign_single_manifest(self, pullspec: str) -> bool:
        """ use sigstore to sign a single image manifest and upload the signature
        :param pullspec: Pullspec to be signed
        """
        log = self._logger
        cmd = ["cosign", "sign", "--key", f"awskms:///{self.signing_key_id}", pullspec]
        env=os.environ | {"AWS_CONFIG_FILE": self.signing_creds}
        if self.runtime.dry_run:
            log.debug("[DRY RUN] Would have signed image: %s", cmd)
            return True

        log.debug("Signing %s...", pullspec)
        rc, stdout, stderr = await exectools.cmd_gather_async(cmd, check=False, env=os.environ.copy())
        if rc:
            log.error("Failure signing %s:\n%s", pullspec, stderr)
            return False

        log.debug("Successfully signed %s:\n%s", pullspec, stdout)
        return True

    @staticmethod
    async def get_release_image_references(pullspec: str) -> List[str]:
        # Retrieve pullspecs that the release image references
        return list(
            tag["from"]["name"]
            for tag in (await get_release_image_info(pullspec))["references"]["spec"]["tags"]
        )


@cli.command("cosign-container")
@click.option("-g", "--group", metavar='NAME', required=True,
              help="The group of components on which to operate. e.g. openshift-4.15")
@click.option("-a", "--assembly", metavar="ASSEMBLY_NAME", required=True,
              help="The name of an assembly to be signed. e.g. 4.15.1")
@click.option("--multi", type=click.Choice(("yes", "no", "only")), default="yes",
              help="Whether to sign multi-arch or arch-specific payloads.")
@click.option("--signing-key", type=click.Choice(("prod", "stage")), default="stage",
              help="Key to use for signing: prod or stage")
@click.argument('pullspecs', nargs=-1, required=False)
@pass_runtime
@click_coroutine
async def cosign_container(
        runtime: Runtime, group: str, assembly: str,
        multi: str, signing_key: str,
        pullspecs: Optional[List[str]]=None):
    pipeline = await SigstorePipeline.create(
        runtime, group, assembly,
        multi, signing_key, pullspecs
    )
    await pipeline.run()
