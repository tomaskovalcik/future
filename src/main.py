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

from typing import List, Tuple, Union
from regular_expressions import PATTERNS
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
    def zip(files: List[str]):
        """
        this method should compress all files that were found into a single zip file.
        """
        pass


class CoreController:
    def __init__(self, root=".", report_file=None):
        self.root = root
        self._found_patterns: List[Match] = []
        self.report_file = report_file or self.generate_filename()
        self.hashed_files: List[HashedFile] = []
        self.file_operator = FileOperator()

    @staticmethod
    def generate_filename():
        return time.strftime("%Y%m%d-%H%M%S") + " wallet-forensic"

    @staticmethod
    def inappropriate_format(file: str):
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

    def main(self):
        process_snapshot = self.get_running_processes()

        current = Path(self.root)
        current_absolute = str(current.absolute())
        for root, _, files in os.walk(current_absolute):
            for file in files:
                abs_path = root + "/" + file
                if self.inappropriate_format(abs_path):
                    continue
                self.search_for_pattern(abs_path)

        files = [match.file for match in self._found_patterns]
        files = set(files)

        for file in files:
            fingerprint = self.touch_sha256(Path(file))
            self.hashed_files.append(HashedFile(file, fingerprint))

        self.file_operator.write(
            "process_snapshot.txt", process_snapshot.stdout.decode("utf-8")
        )
        self.file_operator.write_csv("hashed_files.csv", self.hashed_files)
        self.file_operator.write_csv("found_patterns.csv", self._found_patterns)

    def add_match(self, match: Match) -> None:
        self._found_patterns.append(match)

    def search_for_pattern(self, file, mode="rb"):
        for i, line in enumerate(open(file, mode)):
            for key in PATTERNS.keys():
                match = re.search(PATTERNS[key], line)
                if match:
                    self.add_match(Match(file, match.group().decode("utf-8"), key))

    @staticmethod
    def get_running_processes() -> subprocess.CompletedProcess:
        # should return something list or tuple of running processes or just save the current process list
        # for later analysis
        return subprocess.run(["ps", "-eo", "pid,args"], capture_output=True)

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

    # def decode_base58(self, bc, length):
    #     digits58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    #     n = 0
    #     for char in bc:
    #         n = n * 58 + digits58.index(char)
    #     return n.to_bytes(length, "big")
    #
    # def check_bc(self, bc):
    #     try:
    #         bcbytes = self.decode_base58(bc, 25)
    #         return (
    #             bcbytes[-4:]
    #             == hashlib.sha256(hashlib.sha256(bcbytes[:-4]).digest()).digest()[:4]
    #         )
    #     except Exception:
    #         return False


def main():
    # not really important now, does not do anything
    parser = argparse.ArgumentParser(description="Look for bitcoin artifacts")
    parser.add_argument("--fast", help="Performs fast scan of /home directory")
    args = parser.parse_args()
    print(args)

    c = CoreController("/home/tom/erazmus")
    c.main()


if __name__ == "__main__":
    main()
