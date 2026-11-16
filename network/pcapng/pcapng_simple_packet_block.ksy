# Copyright 2026 Neaera Consulting LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
meta:
  id: pcapng_simple_packet_block
  title: pcapng Simple Packet Block
  license: Apache-2.0
  ks-version: '0.11'
  endian:
    switch-on: is_le
    cases:
      true: le
      false: be
doc: |
  The body of a Simple Packet Block: a packet with no timestamp and no options,
  captured on the section's first interface.
doc-ref: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
params:
  - id: is_le
    type: bool
    doc: |
      True if the section is little-endian. `pcapng` passes the section's
      byte order, which a type in another file can't inherit.
seq:
  - id: len_original
    type: u4
  - id: packet_data_and_padding
    size-eos: true
    doc: |
      The packet data followed by padding. The length of the packet data is
      the smallest of `len_original`, the size of this field, and the snaplen
      of the section's first interface. A snaplen of 0 is left out of the
      comparison.
