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
  id: ieee802_11
  title: IEEE 802.11 MAC frame
  license: Apache-2.0
  imports:
    - /network/ipv4_packet
    - /network/ipv6_packet
  endian: le
  bit-endian: le
doc: |
  The MAC header of an IEEE 802.11 (Wi-Fi) frame. For unencrypted data
  frames, this spec also parses the LLC header and the protocol that it
  names. Other frames keep their body as raw bytes.

  Control frames have a varying set of addresses after the first one. Those
  addresses stay in the raw body.
params:
  - id: has_fcs
    type: bool
    doc: |
      True when the last 4 bytes of the frame are a frame check sequence. The
      frame itself does not say whether it has one, so the caller supplies
      this.
seq:
  - id: protocol_version
    type: b2
  - id: frame_type
    type: b2
    enum: frame_type_enum
  - id: subtype
    type: b4
  - id: to_ds
    type: b1
  - id: from_ds
    type: b1
  - id: more_fragments
    type: b1
  - id: retry
    type: b1
  - id: power_management
    type: b1
  - id: more_data
    type: b1
  - id: is_protected
    type: b1
  - id: order
    type: b1
  - id: duration
    type: u2
  - id: addr1
    size: 6
  - id: addr2
    size: 6
    if: frame_type != frame_type_enum::control
  - id: addr3
    size: 6
    if: frame_type != frame_type_enum::control
  - id: sequence_control
    type: u2
    if: frame_type != frame_type_enum::control
  - id: addr4
    size: 6
    if: frame_type == frame_type_enum::data and to_ds and from_ds
  - id: qos_control
    type: u2
    if: is_qos
  - id: ht_control
    type: u4
    if: order and (is_qos or frame_type == frame_type_enum::management)
  - id: llc
    type: llc
    size: '_io.size - _io.pos - (has_fcs ? 4 : 0)'
    if: has_llc
  - id: body
    size: '_io.size - _io.pos - (has_fcs ? 4 : 0)'
    if: not has_llc
  - id: fcs
    type: u4
    if: has_fcs
instances:
  is_qos:
    value: frame_type == frame_type_enum::data and (subtype & 8) != 0
  has_llc:
    value: frame_type == frame_type_enum::data and (subtype & 4) == 0 and not is_protected
types:
  llc:
    doc: |
      An LLC header with SNAP, a bare EtherType (EPD, used by IEEE 1609), or
      another LLC header. The first two bytes tell them apart: AA AA starts
      SNAP, and 88 DC is the WSMP EtherType. Other LLC headers can start with
      almost any value, including values that look like EtherTypes, so no
      other value is treated as EPD.
    seq:
      - id: first
        type: u2be
      - id: snap_control
        type: u1
        if: is_snap
      - id: snap_oui
        size: 3
        if: is_snap
      - id: snap_ether_type
        type: u2be
        if: is_snap
      - id: body
        size-eos: true
        type:
          switch-on: ether_type
          cases:
            0x0800: ipv4_packet
            0x86dd: ipv6_packet
    instances:
      is_snap:
        value: first == 0xaaaa
      is_epd:
        value: first == 0x88dc
      ether_type:
        value: 'is_snap ? snap_ether_type : (is_epd ? first : 0)'
enums:
  frame_type_enum:
    0: management
    1: control
    2: data
    3: extension
