import click
from errata_tool import Erratum
from pyartcd import constants, util
from pyartcd.cli import cli, click_coroutine, pass_runtime
from pyartcd.runtime import Runtime


class OperatorPrereleasePipeline:
    def __init__(self, runtime: Runtime, group: str, assembly: str, early_silent: bool):
        self.runtime = runtime
        self._logger = runtime.logger
        self.assembly = assembly
        self.group = group
        self.early_silent = early_silent
        self.advisory_id = None

    async def run(self):
        # load relevant group/assembly config
        # determine or create an advisory
        # populate with correct bundles (per assembly)
        # gather dependencies
        group_config = await util.load_group_config(self.group, self.assembly, env=os.environ.copy())
        if self.assembly in ["stream", "test"]:
            raise ValueError("Cannot record advisories without a named non-stream assembly.")
        self.advisory_id = group_config.get("advisories", {}).get("metadata")

        # just BS below
        advisory = Erratum(errata_id=self.extra_ad_id)
        self._logger.info("Check advisory status ...")
        if advisory.errata_state in ["QE", "NEW_FILES"]:
            raise ValueError("Advisory status not in REL_PREP yet ...")
        if advisory.errata_state == "SHIPPED_LIVE":
            self._logger.info("Advisory status already in SHIPPED_LIVE, update subtask 9 ...")
            self._jira_client.complete_subtask(self.parent_jira_key, 8, "Advisory status already in SHIPPED_LIVE")
        self._logger.info("Advisory status already in post REL_PREP, update subtask 7 ...")
        self._jira_client.complete_subtask(self.parent_jira_key, 6, "Advisory status already in REL_PREP")


@cli.command("operator-prerelease")
@click.option("-g", "--group", metavar='NAME', required=True,
              help="The group of components on which to operate. e.g. openshift-4.14")
@click.option("--assembly", metavar="ASSEMBLY_NAME", required=True,
              help="The name of an assembly. e.g. rc.1")
@click.option("--early-silent", is_flag=True,
              help="Prepare an early silent release (GA-ready with bugs associated)")
@pass_runtime
@click_coroutine
async def operator_prerelease(runtime: Runtime, group: str, assembly: str, early_silent: bool):
    await OperatorPrereleasePipeline(runtime, group, assembly, early_silent).run()
