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

from typing import List, Tuple, Union
from regular_expressions import PATTERNS, EXODUS, ELECTRUM
from dataclasses import dataclass

DEFAULT_EXODUS = "~/.config/Exodus"
DEFAULT_ELECTRUM = "~/.electrum"


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

    @staticmethod
    def write(file, obj: str):
        with open(file, "w") as f:
            f.write(obj)

    @staticmethod
    def write_csv(file, container: List[Union[Match, HashedFile]]):
        with open(file, "w", newline="") as csvfile:
            fieldnames = [column for column in container[0].__dict__.keys()]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for item in container:
                writer.writerow(item.__dict__)

    @staticmethod
    def compress(files: List[str]):
        with ZipFile("testzipwallet.zip", "w") as zipfile:
            for file in files:
                zipfile.write(file)


class Controller:
    def __init__(self, root=".", report_file_name=None):
        self.root: str = root
        self._found_patterns: List[Match] = []
        self.report_file: str = report_file_name or self.generate_filename()
        self.hashed_files: List[HashedFile] = []
        self.file_operator = FileOperator()
        self.processor = Processor()

    @staticmethod
    def generate_filename() -> str:
        return time.strftime("%Y%m%d-%H%M%S") + " wallet-forensic"

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

    def main(self) -> None:
        process_snapshot = self.processor.get_running_processes()
        command_history = self.processor.examine_command_history()
        indication = self.processor.examine_process_snapshot(process_snapshot)

        current = Path(self.root)
        current_absolute = str(current.absolute())
        for root, _, files in os.walk(current_absolute):
            for file in files:
                abs_path = root + "/" + file
                if self.inappropriate_format(abs_path):
                    continue
                self.search_for_pattern(abs_path)

        files = [match.file for match in self._found_patterns]
        files = list(set(files))

        for file in files:
            fingerprint = self.touch_sha256(Path(file))
            self.hashed_files.append(HashedFile(file, fingerprint))

        self.file_operator.write(
            "process_snapshot.txt", process_snapshot.stdout.decode("utf-8")
        )
        self.file_operator.write_csv("hashed_files.csv", self.hashed_files)
        self.file_operator.write_csv("found_patterns.csv", self._found_patterns)
        self.file_operator.compress(files)

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
                    self.add_match(Match(file, match.group().decode("utf-8"), key))

    def touch_sha256(self, file: Path) -> str:
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
    # not really important now, does not do anything
    parser = argparse.ArgumentParser(description="Look for bitcoin artifacts")
    parser.add_argument("--fast", help="Performs fast scan of /home directory")
    args = parser.parse_args()

    c = Controller("/home/tom/erazmus")
    c.main()


if __name__ == "__main__":
    main()
