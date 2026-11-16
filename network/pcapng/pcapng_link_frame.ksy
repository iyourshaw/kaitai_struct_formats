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
  id: pcapng_link_frame
  title: pcapng packet data, read by its interface's link type
  license: Apache-2.0
  ks-version: '0.11'
  imports:
    - /network/ethernet_frame
    - /network/packet_ppi
    - /network/radiotap
    - /network/ieee802_11
    - /network/linux_sll
doc: |
  The data of one packet from a pcapng file, parsed by the link type of the
  interface it was captured on. Pass it a packet's `packet_data` (or the
  captured part of a Simple Packet Block's data) and the `link_type` of the
  Interface Description Block that the packet's `interface_id` refers to.

  `pcapng` can't do this itself: each interface has its own link type, and a
  Kaitai Struct expression cannot find the matching Interface Description
  Block among a section's blocks. So `pcapng` leaves packet data as raw bytes,
  and this spec parses it. Link types without a case here stay as raw bytes.
  The cases are the same as the link-layer cases in `pcap`'s packet body.
doc-ref: https://www.tcpdump.org/linktypes.html
params:
  - id: link_type
    type: u2
    doc: A value from the tcpdump LINKTYPE registry (`pcap::linktype`).
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
