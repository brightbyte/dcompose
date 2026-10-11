"""The few docker operations the gate needs, as thin wrappers around the real binary."""

import io
import json
import subprocess
import tarfile

MAX_FILE_BYTES = 1 << 20  # /etc/passwd and /etc/group come from a hostile image


class DockerError(Exception):
    pass


class Docker:
    def __init__(self, binary, run=subprocess.run, call=subprocess.call, popen=subprocess.Popen):
        """binary: the real docker (realdocker.locate)."""
        self.binary = binary
        self.run, self.call, self.popen = run, call, popen

    def create(self, args):
        """(exit code, container id or None). stderr stays on the terminal so pull progress shows."""
        result = self.run([self.binary, "create", *args], stdout=subprocess.PIPE, text=True)
        return result.returncode, (result.stdout.strip() if result.returncode == 0 else None)

    def inspect_container(self, ref):
        return self._inspect("container", ref)

    def inspect_image(self, ref):
        return self._inspect("image", ref)

    def _inspect(self, kind, ref):
        result = self.run([self.binary, kind, "inspect", "--", ref], capture_output=True, text=True)
        if result.returncode != 0:
            raise DockerError(result.stderr.strip() or f"docker {kind} inspect failed")
        return json.loads(result.stdout)[0]

    def read_file(self, container, path):
        """Contents of a file in a container that has not been started, or None if it is not there.

        Raises DockerError if the file is larger than MAX_FILE_BYTES.
        """
        process = self.popen([self.binary, "cp", "-L", f"{container}:{path}", "-"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        data = process.stdout.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            process.kill()
            process.wait()
            raise DockerError(f"{path} in the image is larger than {MAX_FILE_BYTES} bytes")
        if process.wait() != 0:
            return None
        return first_file_of_tar(data)

    def start(self, container, attach, interactive, detach_keys):
        args = ["start"]
        if attach:
            args.append("--attach")
        if interactive:
            args.append("--interactive")
        if detach_keys:
            args.append(f"--detach-keys={detach_keys}")
        return self.call([self.binary, *args, "--", container])

    def remove(self, container):
        self.run([self.binary, "rm", "--force", "--", container], capture_output=True)

    def context(self):
        result = self.run([self.binary, "context", "show"], capture_output=True, text=True)
        return result.stdout.strip() if result.returncode == 0 else None


def first_file_of_tar(data):
    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            member = archive.next()
            if member is None or not member.isreg():
                return None
            return archive.extractfile(member).read().decode("utf-8", errors="replace")
    except tarfile.TarError:
        return None
