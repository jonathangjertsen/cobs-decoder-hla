from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, NumberSetting

"""
The sections below were adapted from

* https://github.com/cmcqueen/cobs-python/blob/main/python3/cobs/cobs/_cobs_py.py
* https://github.com/cmcqueen/cobs-python/blob/main/python3/cobs/cobsr/_cobsr_py.py

Original license:

----------------------------------------------------------------------------
Copyright (c) 2010 Craig McQueen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
----------------------------------------------------------------------------
"""
class DecodeError(Exception):
    pass

def _get_buffer_view(in_bytes):
    mv = memoryview(in_bytes)
    if mv.ndim > 1 or mv.itemsize > 1:
        raise BufferError('object must be a single-dimension buffer of bytes.')
    try:
        mv = mv.cast('c')
    except AttributeError:
        pass
    return mv

def decode_cobs(in_bytes):
    """Decode a string using Consistent Overhead Byte Stuffing (COBS).
    
    Input should be a byte string that has been COBS encoded. Output
    is also a byte string.
    
    A cobs.DecodeError exception will be raised if the encoded data
    is invalid."""
    if isinstance(in_bytes, str):
        raise TypeError('Unicode-objects are not supported; byte buffer objects only')
    in_bytes_mv = _get_buffer_view(in_bytes)
    out_bytes = bytearray()
    idx = 0

    if len(in_bytes_mv) > 0:
        while True:
            length = ord(in_bytes_mv[idx])
            if length == 0:
                raise DecodeError("zero byte found in input")
            idx += 1
            end = idx + length - 1
            copy_mv = in_bytes_mv[idx:end]
            if b'\x00' in copy_mv:
                raise DecodeError("zero byte found in input")
            out_bytes += copy_mv
            idx = end
            if idx > len(in_bytes_mv):
                raise DecodeError("not enough input bytes for length code")
            if idx < len(in_bytes_mv):
                if length < 0xFF:
                    out_bytes.append(0)
            else:
                break
    return bytes(out_bytes)


def decode_cobsr(in_bytes):
    """Decode a string using Consistent Overhead Byte Stuffing/Reduced (COBS/R).
    
    Input should be a byte string that has been COBS/R encoded. Output
    is also a byte string.
    
    A cobsr.DecodeError exception will be raised if the encoded data
    is invalid. That is, if the encoded data contains zeros."""
    if isinstance(in_bytes, str):
        raise TypeError('Unicode-objects are not supported; byte buffer objects only')
    in_bytes_mv = _get_buffer_view(in_bytes)
    out_bytes = bytearray()
    idx = 0

    if len(in_bytes_mv) > 0:
        while True:
            length = ord(in_bytes_mv[idx])
            if length == 0:
                raise DecodeError("zero byte found in input")
            idx += 1
            end = idx + length - 1
            copy_mv = in_bytes_mv[idx:end]
            if b'\x00' in copy_mv:
                raise DecodeError("zero byte found in input")
            out_bytes += copy_mv
            idx = end
            if idx > len(in_bytes_mv):
                out_bytes.append(length)
                break
            elif idx < len(in_bytes_mv):
                if length < 0xFF:
                    out_bytes.append(0)
            else:
                break
    return bytes(out_bytes)


"""
End of adapted section
"""

class CobsXDecoder(HighLevelAnalyzer):
    result_types = {
        "Message": {
            "format": "{{data.data}}"
        },
        "Error": {
            "format": "ERROR: {{data.error}}"
        }
    }
    number_of_prefix_bytes_after_0_byte = NumberSetting(min_value = 0, max_value = 10)

    def decode_bytes(self, x):
        pass

    def __init__(self):
        self.received = []
        self.frame_start_time = None
        self.frame_end_time = None

    def decode(self, frame: AnalyzerFrame):
        retval = None
        data = frame.data["data"]

        if self.frame_start_time is None:
            self.frame_start_time = frame.start_time

        if data == b"\0":
            if len(self.received) >= self.number_of_prefix_bytes_after_0_byte:
                del self.received[:int(self.number_of_prefix_bytes_after_0_byte)]
            if self.received:
                try:
                    data = self.decode_bytes(b"".join(self.received))
                    retval = AnalyzerFrame(
                        "Message",
                        self.frame_start_time,
                        self.frame_end_time,
                        {
                            "data": data,
                        }
                    )
                except DecodeError as de:
                    retval = AnalyzerFrame(
                        "Error",
                        self.frame_start_time,
                        self.frame_end_time,
                        {
                            "error": str(de),
                        }
                    )
            self.received = []
            self.frame_start_time = frame.start_time
        else:
            self.received.append(data)
            self.frame_end_time = frame.end_time
        return retval


class CobsDecoder(CobsXDecoder):
    def decode_bytes(self, x):
        return decode_cobs(x)


class CobsrDecoder(CobsXDecoder):
    def decode_bytes(self, x):
        return decode_cobsr(x)
