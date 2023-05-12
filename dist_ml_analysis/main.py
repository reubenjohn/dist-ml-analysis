import struct
import sys
import threading

import matplotlib.pyplot as plt
import pyshark

output_lock = threading.Lock()


class LineOffsetStreamWrapper:
    UP = '\033[F'
    DOWN = '\033[B'

    def __init__(self, lines=0, stream=sys.stderr):
        self.stream = stream
        self.lines = lines

    def write(self, data):
        with output_lock:
            self.stream.write(self.UP * self.lines)
            self.stream.write(data)
            self.stream.write(self.DOWN * self.lines)
            self.stream.flush()

    def __getattr__(self, name):
        return getattr(self.stream, name)


def main():
    capture = pyshark.FileCapture('experiments/experiment1-receiver.pcapng')
    timestamps = [(struct.unpack('<I', bytes.fromhex(packet.DATA.data[:8]))[0], packet.sniff_time)
                  # for packet in capture
                  for i, packet in zip(range(1001), capture)
                  if packet.transport_layer == 'UDP' and packet.highest_layer == 'DATA']
    diffs = [[cur[0], (nxt[1] - cur[1]).total_seconds()] for nxt, cur in zip(timestamps[1:], timestamps)]
    x, y = zip(*diffs)
    # plt.hist(diffs, bins=200)
    plt.scatter(x, y)
    plt.show()

    plt.hist(y, bins=200)
    plt.show()


if __name__ == '__main__':
    main()
