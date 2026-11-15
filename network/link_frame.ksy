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
  id: link_frame
  title: A captured packet, read by its link type
  license: Apache-2.0
  imports:
    - /network/ethernet_frame
    - /network/packet_ppi
    - /network/radiotap
    - /network/ieee802_11
    - /network/linux_sll
doc: |
  The data of one captured packet, parsed by a link type that the caller
  supplies. A pcapng file gives each interface its own link type, and a
  Kaitai Struct expression cannot find the matching Interface Description
  Block among a section's blocks. For that reason, `pcapng` leaves packet
  data as raw bytes, and this spec parses it. Link types without a case here
  stay as raw bytes.
params:
  - id: link_type
    type: u2
    doc: A value from the tcpdump LINKTYPE registry.
seq:
  - id: body
    size-eos: true
    type:
      switch-on: link_type
      cases:
        1: ethernet_frame
        105: ieee802_11(false)
        113: linux_sll
        127: radiotap
        192: packet_ppi
