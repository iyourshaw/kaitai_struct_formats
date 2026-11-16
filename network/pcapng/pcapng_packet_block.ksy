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
  id: pcapng_packet_block
  title: pcapng Packet Block (obsolete)
  license: Apache-2.0
  ks-version: '0.11'
  imports:
    - /network/pcapng/pcapng_options
  endian:
    switch-on: is_le
    cases:
      true: le
      false: be
doc: |
  The body of the obsolete Packet Block. Writers must not write it, but readers
  can find it in old files.
doc-ref: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
params:
  - id: is_le
    type: bool
    doc: |
      True if the section is little-endian. `pcapng` passes the section's
      byte order, which a type in another file can't inherit.
seq:
  - id: interface_id
    type: u2
  - id: drops_count
    type: u2
  - id: ts_high
    type: u4
  - id: ts_low
    type: u4
  - id: len_packet_data
    type: u4
  - id: len_original
    type: u4
  - id: packet_data
    size: len_packet_data
  - id: padding
    size: (4 - len_packet_data % 4) % 4
  - id: options
    type: pcapng_options(is_le, pcapng_options::option_kind::packet)
