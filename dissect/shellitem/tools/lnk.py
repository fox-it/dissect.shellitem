import argparse
import logging
from pathlib import PosixPath

from dissect.shellitem.lnk import Lnk
from dissect.util import ts

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


def parse(path: str):

    lnk_file = Lnk(path)
    lnk_net_name = lnk_device_name = None

    if lnk_file.link_header:
        lnk_path = path
        lnk_name = lnk_file.stringdata.name_string.string if lnk_file.flags.has_name else None

        lnk_mtime = ts.from_unix(path.stat().st_mtime)
        lnk_atime = ts.from_unix(path.stat().st_atime)
        lnk_ctime = ts.from_unix(path.stat().st_ctime)

        lnk_relativepath = lnk_file.stringdata.relative_path.string if lnk_file.flags.has_relative_path else None
        lnk_workdir = lnk_file.stringdata.working_dir.string if lnk_file.flags.has_working_dir else None
        lnk_iconlocation = lnk_file.stringdata.icon_location.string if lnk_file.flags.has_icon_location else None
        lnk_arguments = lnk_file.stringdata.command_line_arguments.string if lnk_file.flags.has_arguments else None
        local_base_path = (
            lnk_file.linkinfo.local_base_path.decode("raw_unicode_escape")
            if lnk_file.flags.has_link_info and lnk_file.linkinfo.flags.volumeid_and_local_basepath
            else None
        )
        common_path_suffix = (
            lnk_file.linkinfo.common_path_suffix.decode("raw_unicode_escape") if lnk_file.flags.has_link_info else None
        )

        if local_base_path and common_path_suffix:
            lnk_full_path = local_base_path + common_path_suffix
        elif local_base_path and not common_path_suffix:
            lnk_full_path = local_base_path
        else:
            lnk_full_path = None

        if lnk_file.flags.has_link_info:
            if lnk_file.linkinfo.flags.common_network_relative_link_and_pathsuffix:
                lnk_net_name = (
                    lnk_file.linkinfo.common_network_relative_link.net_name.decode("raw_unicode_escape")
                    if lnk_file.linkinfo.common_network_relative_link.net_name
                    else None
                )
                lnk_device_name = (
                    lnk_file.linkinfo.common_network_relative_link.device_name.decode("raw_unicode_escape")
                    if lnk_file.linkinfo.common_network_relative_link.device_name
                    else None
                )

        try:
            machine_id = lnk_file.extradata.TRACKER_PROPS.machine_id.decode()
        except AttributeError:
            machine_id = None

        target_mtime = ts.wintimestamp(lnk_file.link_header.write_time)
        target_atime = ts.wintimestamp(lnk_file.link_header.access_time)
        target_ctime = ts.wintimestamp(lnk_file.link_header.creation_time)

        print(
            "Link Path\t\t\t: {}\n"
            "Link Name / description\t\t: {}\n"
            "Link modification time\t\t: {}\n"
            "Link access time\t\t: {}\n"
            "Link changed time\t\t: {}\n"
            "Link relative path\t\t: {}\n"
            "Link working directory\t\t: {}\n"
            "Link icon location\t\t: {}\n"
            "Link arguments\t\t\t: {}\n"
            "Link local base path\t\t: {}\n"
            "Link common path suffix\t\t: {}\n"
            "Link full path\t\t\t: {}\n"
            "Net name link\t\t\t: {}\n"
            "Device name link\t\t: {}\n"
            "Machine id link\t\t\t: {}\n"
            "Target file modification time\t: {}\n"
            "Target file access time\t\t: {}\n"
            "Target file changed time\t: {}".format(
                lnk_path,
                lnk_name,
                lnk_mtime,
                lnk_atime,
                lnk_ctime,
                lnk_relativepath,
                lnk_workdir,
                lnk_iconlocation,
                lnk_arguments,
                local_base_path,
                common_path_suffix,
                lnk_full_path,
                lnk_net_name,
                lnk_device_name,
                machine_id,
                target_mtime,
                target_atime,
                target_ctime,
            )
        )


def main():

    parser = argparse.ArgumentParser(
        description="Parse a .lnk file from a target or from local disk.",
    )

    parser.add_argument("path", metavar="path", type=str, help="Path to .lnk file(s).")

    args = parser.parse_args()
    path = PosixPath(args.path)
    parse(path)


if __name__ == "__main__":
    main()
