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
  id: pcapng_interface_description_block
  title: pcapng Interface Description Block
  license: Apache-2.0
  ks-version: '0.11'
  imports:
    - /network/pcap
    - /network/pcapng/pcapng_options
  endian:
    switch-on: is_le
    cases:
      true: le
      false: be
doc: |
  The body of an Interface Description Block. Each one describes an interface
  that packets were captured on: its link type, its snaplen, and options such as
  its name and timestamp resolution (`if_tsresol`, `if_tsoffset`). Packet blocks
  refer to interfaces by their position among the section's Interface
  Description Blocks.
doc-ref: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
params:
  - id: is_le
    type: bool
    doc: |
      True if the section is little-endian. `pcapng` passes the section's
      byte order, which a type in another file can't inherit.
seq:
  - id: link_type
    type: u2
    enum: pcap::linktype
  - id: reserved
    size: 2
  - id: snaplen
    type: u4
    doc: |
      The maximum number of bytes captured from each packet. A value of 0
      means there is no limit.
  - id: options
    type: pcapng_options(is_le, pcapng_options::option_kind::interface_description)
