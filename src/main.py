# https://support.exodus.com/article/80-how-do-i-delete-my-wallet-and-start-over#
# https://electrum.readthedocs.io/en/latest/faq.html
# https://support.exodus.com/article/767-how-do-i-keep-my-money-safe#
# https://www.reddit.com/r/ExodusWallet/comments/gfxj96/which_folder_in_pc_holds_the_secret_keys/
# https://bitcointalk.org/index.php?topic=2124293.0
# https://bitcointalk.org/index.php?topic=325364.0
# https://github.com/bitcoin/bitcoin/blob/master/doc/files.md
# https://en.bitcoin.it/wiki/Data_directory

import re
import argparse
import subprocess
import hashlib
from pathlib import Path
import os
import time
import csv
from zipfile import ZipFile


from typing import List, Union
from regular_expressions import PATTERNS, EXODUS, ELECTRUM
from dataclasses import dataclass


@dataclass
class Match:
    file: str
    hit: str
    type: str


@dataclass
class HashedFile:
    file: str
    fingerprint: str


class Processor:
    def __init__(self):
        self.host_information = os.uname()

    def get_host_information(self) -> str:
        return (
            f"sysname={self.host_information.sysname}, "
            f"nodename={self.host_information.nodename}, "
            f"release={self.host_information.release}, "
            f"version={self.host_information.version}, "
            f"machine={self.host_information.machine}"
        )

    @staticmethod
    def examine_process_snapshot(process_snapshot: subprocess.CompletedProcess) -> bool:
        """
        check current running processes and return number
        of indications that some crypto process might be running in
        the backround
        """
        if re.search(EXODUS, process_snapshot.stdout) or re.search(
            ELECTRUM, process_snapshot.stdout
        ):
            return True
        return False

    @staticmethod
    def get_running_processes() -> subprocess.CompletedProcess:
        # should return something list or tuple of running processes or just save the current process list
        # for later analysis
        return subprocess.run(["ps", "-eo", "pid,args"], capture_output=True)

    @staticmethod
    def examine_command_history() -> bool:
        path = Path("~/.bash_history")
        if path.expanduser().exists():
            with open(path.expanduser(), "rb") as file:
                for line in file:
                    if re.search(EXODUS, line) or re.search(ELECTRUM, line):
                        return True
        return False


class FileOperator:
    """
    A job of this class is to provide an interface to
    perform operations on files that were created during digital forensic
    compression, writing to files (CSV, txt).
    """

    def __init__(self, run_name):
        self._run_name = run_name
        self._run_timestamp = time.strftime("%Y%m%d-%H%M%S")

    def write(self, obj: str, unique_id=""):
        filename = self.generate_filename(unique_id=unique_id, suffix=".txt")
        with open(filename, "w") as f:
            f.write(obj)

    def write_csv(self, container: List[Union[Match, HashedFile]], unique_id=""):
        filename = self.generate_filename(unique_id=unique_id, suffix=".csv")
        with open(filename, "w", newline="") as csvfile:
            fieldnames = [column for column in container[0].__dict__.keys()]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for item in container:
                writer.writerow(item.__dict__)

    def compress(self, container: List[str], unique_id=""):
        filename = self.generate_filename(unique_id=unique_id, suffix=".zip")
        with ZipFile(filename, "w") as zipfile:
            for file in container:
                zipfile.write(file)

    def generate_filename(self, unique_id="", suffix="") -> str:
        return f"{self._run_name}-{self._run_timestamp}-{unique_id}{suffix}"


class Controller:
    def __init__(
        self,
        root=".",
        run_name=None,
        target_wallet=None,
        verbose: bool = False,
        silent: bool = False,
    ):
        self.root: str = root
        self._found_patterns: List[Match] = []
        self.run_name: str = run_name
        self.hashed_files: List[HashedFile] = []
        self.file_operator = FileOperator(run_name)
        self.processor = Processor()
        self.verbose = verbose
        self.silent = silent
        self.target_wallet = target_wallet
        self.default_wallets_paths = {
            "exodus": "~/.config/Exodus",
            "electrum": "~/.electrum",
        }

    @staticmethod
    def inappropriate_format(file: str) -> bool:
        """
        should check if file is executable binary
        if it is return True, else return False
        i anticipate that this will be needed once a big files we'll be opened.
        """
        return Path(file).suffix in [
            ".zip",
            ".tar",
            ".gzip",
            ".7z",
            ".mp3",
            ".mp4",
            ".avi",
            ".jpg",
            ".png",
            ".gif",
        ]

    def _resolve_path(
        self,
    ) -> Path.absolute:
        current = Path(self.root)
        current.expanduser()
        return current.absolute()

    def specific_wallet_check(self):
        path = (
            Path(self.default_wallets_paths[self.target_wallet]).expanduser().absolute()
        )
        if not path.exists():
            return False
        return True

    def main(self) -> None:
        process_snapshot = self.processor.get_running_processes()
        command_history = self.processor.examine_command_history()
        indication = self.processor.examine_process_snapshot(process_snapshot)

        if self.target_wallet:
            print(self.specific_wallet_check())

        current_absolute = self._resolve_path()
        for root, _, files in os.walk(current_absolute):
            for file in files:
                abs_path = root + "/" + file
                if self.inappropriate_format(abs_path):
                    continue
                self.search_for_pattern(abs_path)

        files = [match.file for match in self._found_patterns]
        files = list(set(files))
        for file in files:
            fingerprint = self._touch_sha256(Path(file))
            self.hashed_files.append(HashedFile(file, fingerprint))

        # TODO: remove if/else in the final version
        if not self.silent:
            pass
        else:
            self.file_operator.write(
                process_snapshot.stdout.decode("utf-8"), unique_id="process_snapshot"
            )
            self.file_operator.write_csv(
                unique_id="hashed_files", container=self.hashed_files
            )
            self.file_operator.write_csv(
                unique_id="artefacts", container=self._found_patterns
            )
            self.file_operator.compress(container=files)

        print(f"Found {len(files)} files containing bitcoin related patterns")
        print(f"Wallet/bitcoin processes running: {indication}")
        print(f"Wallet/bitcoin command used: {command_history}")

    def add_match(self, match: Match) -> None:
        self._found_patterns.append(match)

    def search_for_pattern(self, file: str, mode="rb"):
        for i, line in enumerate(open(file, mode)):
            for key in PATTERNS.keys():
                match = re.search(PATTERNS[key], line)
                if match:
                    if self.verbose:
                        print(f"Match found in file: {file}")
                    self.add_match(Match(file, match.group().decode("utf-8"), key))

    def _touch_sha256(self, file: Path) -> str:
        # solution obtained from the following link:
        # https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
        h = hashlib.sha256()
        with open(file, "rb") as bin_file:
            while True:
                chunk = bin_file.read(h.block_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Look for bitcoin artifacts")
    group_wallets = parser.add_mutually_exclusive_group()
    parser.add_argument("--name", "-n", help="Name of the run", required=True)
    parser.add_argument(
        "--directory",
        "-d",
        help="Root directory to start the scan from. If not specified, then current directory is the root directory",
        default=".",
    )
    group_wallets.add_argument(
        "--exodus",
        help="Search only for Exodus related files.",
        action="store_true",
    )
    group_wallets.add_argument(
        "--electrum",
        help="Search only for Electrum related files.",
        action="store_true",
    )
    parser.add_argument(
        "--verbose", "-v", help="Verbosely list files processed.", action="store_true"
    )

    # this argument is just for development
    # TODO: remove this in the final version
    parser.add_argument(
        "--silent", "-s", help="Do not create any output files", action="store_true"
    )

    args = parser.parse_args()

    if args.exodus:
        target_wallet = "exodus"
    elif args.electrum:
        target_wallet = "electrum"
    else:
        target_wallet = None

    c = Controller(
        root=args.directory,
        run_name=args.name,
        target_wallet=target_wallet,
        verbose=args.verbose,
    )
    c.main()


if __name__ == "__main__":
    main()
