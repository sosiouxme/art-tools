import asyncio
import json
import os
import sys
import click
from typing import Dict, Iterable, List, Optional, Union, Set
from semver import VersionInfo

from pyartcd.signatory import AsyncSignatory
from pyartcd import constants, exectools, util
from pyartcd.cli import cli, click_coroutine, pass_runtime
from pyartcd.oc import get_release_image_info, get_image_info
from pyartcd.runtime import Runtime, GroupRuntime
from artcommonlib.util import run_limited_unordered


CONCURRENCY_LIMIT = 100  # we run out of processes without a limit


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
                 multi: str, pullspecs: Optional[List[str]]
                ) -> None:
        self.runtime = runtime
        self.group = group
        self.assembly = assembly
        self.sign_multi = multi != "no"
        self.sign_arches = multi != "only"
        self.pullspecs = pullspecs

        self.signing_creds = os.environ.get("KMS_CRED_FILE", "dummy-file")
        self.signing_key_id = os.environ.get("KMS_KEY_ID", "dummy-key")

        self._logger = self.runtime.logger

        self._working_dir = self.runtime.working_dir
        self._doozer_working_dir = self._working_dir / "doozer-working"
        self._doozer_env_vars = os.environ.copy()
        self._doozer_env_vars["DOOZER_WORKING_DIR"] = str(self._doozer_working_dir)

    def check_environment_variables(self):
        logger = self.runtime.logger

        required_vars = ["QUAY_USERNAME", "QUAY_PASSWORD", "KMS_CRED_FILE", "KMS_KEY_ID"]

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
            # look up release images we expect to exist, since none were specified.
            self.pullspecs = self._lookup_release_images(release_name)

        # given pullspecs that are most likely trees (either manifest lists or release images),
        # recursively discover all the pullspecs that need to be signed.
        need_signing: Set[str] = set()
        errors: Dict[str, str] = {}  # pullspec -> exception
        need_signing, errors = await self.discover_pullspecs(self.pullspecs, release_name)

        if errors:
            print("Not all pullspecs examined were viable:")
            for ps, err in errors.items():
                print(f"{ps}: {err}")
            exit(1)

        if errors:= await self.sign_pullspecs(need_signing):
            print(f"Not all signings succeeded, check errors: {errors}")
            exit(1)

    def _lookup_release_images(self, release_name):
        # NOTE: only do this for testing purposes. for secure signing, always supply an
        # immutable pullspec with a digest (as tags could theoretically be rewritten in between
        # publishing and signing). TODO: enforce this at invocation time
        arches = []
        if self.sign_arches:
            arches += releases_config.get("group", {}).get("arches") or group_config.get("arches") or []
        if self.sign_multi:
            arches.append("multi")
        return list(f"{constants.RELEASE_IMAGE_REPO}:{release_name}-{arch}" for arch in arches)

    @staticmethod
    def _digestify_pullspec(pullspec, digest):
        """ given an existing pullspec, give the pullspec for a digest in the same repo """
        if len(halves := pullspec.split("@sha256:")) == 2:  # assume that was a digest at the end
            return f"{halves[0]}@{digest}"
        elif len(halves := pullspec.rsplit(":", 1)) == 2:
            # assume that was a tag at the end, while allowing for ":" in the registry spec
            return f"{halves[0]}@{digest}"
        return f"{pullspec}@{digest}"  # assume it was a bare registry/repo

    async def discover_pullspecs(
                self, pullspecs: Iterable[str], release_name: str
            ) -> (Set[str], Dict[str, Exception]):
        """
        recursively discover pullspecs that need signatures.
        :param pullspecs: List of pullspecs to descend from
        :param release_name: Require any release images to have this release name
        :return: a set of pullspecs needing signing, and a dict of any discovery errors
        """
        seen: Set[str] = set(pullspecs)  # prevent re-examination and multiple signings
        need_signing: Set[str] = set()   # pullspecs for manifests to be signed
        errors: Dict[str, Exception] = {}  # pullspec -> error when examining it

        need_examining: List[str] = list(pullspecs)
        while need_examining:
            args = [(ps, release_name) for ps in need_examining]
            results = await run_limited_unordered(self._examine_pullspec, args, CONCURRENCY_LIMIT)

            need_examining = []
            for next_signing, next_examining, next_errors in results:
                need_signing.update(next_signing)
                errors.update(next_errors)
                for ps in next_examining:
                    if ps not in seen:
                        seen.add(ps)
                        need_examining.append(ps)

        return need_signing, errors

    async def _examine_pullspec(
            self, pullspec:str , release_name: str
            ) -> (Set[str], Set[str], Dict[str, Exception]):
        """
        determine what a pullspec is (single manifest, manifest list, release image) and
        recursively add it or its references. limit concurrency or we can run out of processes.
        :param pullspec: Pullspec to be signed
        :param release_name: Require any release images to have this release name
        :return: pullspecs needing signing, pullspecs needing examining, and any discovery errors
        """
        need_signing: Set[str] = set()
        need_examining: Set[str] = set()
        errors: Dict[str, Exception] = {}

        img_info = await get_image_info(pullspec, True)

        if isinstance(img_info, list):  # pullspec is for a manifest list
            for manifest in img_info:
                need_examining.add(self._digestify_pullspec(manifest["name"], manifest["digest"]))
        elif (this_rn := img_info["config"]["config"]["Labels"].get("io.openshift.release")):
            # release image; get references and examine those
            if release_name != this_rn:
                errors[pullspec] = RuntimeError(
                    f"release image at {pullspec} has release name {this_rn}, not the expected {release_name}"
                )
            try:
                for child_spec in await self.get_release_image_references(pullspec):
                    need_examining.add(child_spec)
            except RuntimeError as exc:
                errors[pullspec] = exc
            # also plan to sign the release image itself
            need_signing.add(pullspec)
        else:  # pullspec is for a normal image manifest
            need_signing.add(pullspec)

        return need_signing, need_examining, errors

    async def sign_pullspecs(self, need_signing: Iterable[str]) -> Dict[str, Exception]:
        """
        sign the given pullspecs.
        :param need_signing: Pullspecs to be signed
        :return: dict with any signing errors per pullspec
        """
        args = [(ps, ) for ps in need_signing]
        results = await run_limited_unordered(self._sign_single_manifest, args, CONCURRENCY_LIMIT)
        return {pullspec: err for result in results for pullspec, err in result.items()}

    async def _sign_single_manifest(self, pullspec: str) -> Dict[str, Exception]:
        """ use sigstore to sign a single image manifest and upload the signature
        :param pullspec: Pullspec to be signed
        :return: dict with any signing errors for pullspec
        """
        log = self._logger
        cmd = ["cosign", "sign", "--yes", "--key", f"awskms:///{self.signing_key_id}", pullspec]
        # easier to set AWS_REGION than create AWS_CONFIG_FILE, unless it gets more complicated
        env = os.environ | dict(AWS_SHARED_CREDENTIALS_FILE=self.signing_creds, AWS_REGION="us-east-1")
        if self.runtime.dry_run:
            log.info("[DRY RUN] Would have signed image: %s", cmd)
            return {}

        log.info("Signing %s...", pullspec)
        try:
            rc, stdout, stderr = await exectools.cmd_gather_async(cmd, check=False, env=env)
            if rc:
                log.error("Failure signing %s:\n%s", pullspec, stderr)
                return {pullspec: RuntimeError(stderr)}
        except Exception as exc:
            log.error("Failure signing %s:\n%s", pullspec, exc)
            return {pullspec: exc}

        log.debug("Successfully signed %s:\n%s", pullspec, stdout)
        return {}

    @staticmethod
    async def get_release_image_references(pullspec: str) -> List[str]:
        # Retrieve pullspecs that the release image references
        return list(
            tag["from"]["name"]
            for tag in (await get_release_image_info(pullspec))["references"]["spec"]["tags"]
        )


@cli.command("sigstore-sign")
@click.option("-g", "--group", metavar='NAME', required=True,
              help="The group of components on which to operate. e.g. openshift-4.15")
@click.option("-a", "--assembly", metavar="ASSEMBLY_NAME", required=True,
              help="The name of an assembly to be signed. e.g. 4.15.1")
@click.option("--multi", type=click.Choice(("yes", "no", "only")), default="yes",
              help="Whether to sign multi-arch or arch-specific payloads.")
@click.argument('pullspecs', nargs=-1, required=False)
@pass_runtime
@click_coroutine
async def sigstore_sign_container(
        runtime: Runtime, group: str, assembly: str,
        multi: str, pullspecs: Optional[List[str]]=None):
    pipeline = await SigstorePipeline.create(
        runtime, group, assembly,
        multi, pullspecs
    )
    await pipeline.run()
