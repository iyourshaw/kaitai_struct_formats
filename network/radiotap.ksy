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
  id: radiotap
  title: Radiotap capture header
  license: Apache-2.0
  imports:
    - /network/ieee802_11
  endian: le
doc: |
  A Radiotap header holds metadata about a received or transmitted 802.11
  frame. The capturing machine adds it, and it is never sent on the air. Each
  field has its own alignment, measured from the start of the header.

  This spec reads only the fields named by the first present word. It uses
  the header length to skip the fields named by later present words, vendor
  namespaces and anything else.

  Some drivers do not align their fields correctly, which can push the last
  fields past the header length. Those fields stay unread inside `rest`, so
  the frame after the header can still be parsed.
doc-ref: https://www.radiotap.org/
seq:
  - id: version
    type: u1
  - id: pad
    type: u1
  - id: length
    type: u2
  - id: present
    type: u4
  - id: present_more
    type: u4
    repeat: until
    repeat-until: (_ & 0x80000000) == 0
    if: (present & 0x80000000) != 0
  - id: pad_tsft
    size: (8 - _io.pos % 8) % 8
    if: (present & 0x1) != 0 and (_io.pos + 7) / 8 * 8 + 8 <= length
  - id: tsft
    type: u8
    if: (present & 0x1) != 0 and (_io.pos + 7) / 8 * 8 + 8 <= length
  - id: flags
    type: u1
    if: (present & 0x2) != 0 and _io.pos + 1 <= length
  - id: rate
    type: u1
    if: (present & 0x4) != 0 and _io.pos + 1 <= length
  - id: pad_channel
    size: (2 - _io.pos % 2) % 2
    if: (present & 0x8) != 0 and (_io.pos + 1) / 2 * 2 + 4 <= length
  - id: channel_freq
    type: u2
    if: (present & 0x8) != 0 and (_io.pos + 1) / 2 * 2 + 4 <= length
  - id: channel_flags
    type: u2
    if: (present & 0x8) != 0 and (_io.pos + 1) / 2 * 2 + 2 <= length
  - id: pad_fhss
    size: (2 - _io.pos % 2) % 2
    if: (present & 0x10) != 0 and (_io.pos + 1) / 2 * 2 + 2 <= length
  - id: fhss
    size: 2
    if: (present & 0x10) != 0 and (_io.pos + 1) / 2 * 2 + 2 <= length
  - id: dbm_antenna_signal
    type: s1
    if: (present & 0x20) != 0 and _io.pos + 1 <= length
  - id: dbm_antenna_noise
    type: s1
    if: (present & 0x40) != 0 and _io.pos + 1 <= length
  - id: pad_lock_quality
    size: (2 - _io.pos % 2) % 2
    if: (present & 0x80) != 0 and (_io.pos + 1) / 2 * 2 + 2 <= length
  - id: lock_quality
    type: u2
    if: (present & 0x80) != 0 and (_io.pos + 1) / 2 * 2 + 2 <= length
  - id: pad_tx_attenuation
    size: (2 - _io.pos % 2) % 2
    if: (present & 0x100) != 0 and (_io.pos + 1) / 2 * 2 + 2 <= length
  - id: tx_attenuation
    type: u2
    if: (present & 0x100) != 0 and (_io.pos + 1) / 2 * 2 + 2 <= length
  - id: pad_db_tx_attenuation
    size: (2 - _io.pos % 2) % 2
    if: (present & 0x200) != 0 and (_io.pos + 1) / 2 * 2 + 2 <= length
  - id: db_tx_attenuation
    type: u2
    if: (present & 0x200) != 0 and (_io.pos + 1) / 2 * 2 + 2 <= length
  - id: dbm_tx_power
    type: s1
    if: (present & 0x400) != 0 and _io.pos + 1 <= length
  - id: antenna
    type: u1
    if: (present & 0x800) != 0 and _io.pos + 1 <= length
  - id: db_antenna_signal
    type: u1
    if: (present & 0x1000) != 0 and _io.pos + 1 <= length
  - id: db_antenna_noise
    type: u1
    if: (present & 0x2000) != 0 and _io.pos + 1 <= length
  - id: pad_rx_flags
    size: (2 - _io.pos % 2) % 2
    if: (present & 0x4000) != 0 and (_io.pos + 1) / 2 * 2 + 2 <= length
  - id: rx_flags
    type: u2
    if: (present & 0x4000) != 0 and (_io.pos + 1) / 2 * 2 + 2 <= length
  - id: pad_tx_flags
    size: (2 - _io.pos % 2) % 2
    if: (present & 0x8000) != 0 and (_io.pos + 1) / 2 * 2 + 2 <= length
  - id: tx_flags
    type: u2
    if: (present & 0x8000) != 0 and (_io.pos + 1) / 2 * 2 + 2 <= length
  - id: rts_retries
    type: u1
    if: (present & 0x10000) != 0 and _io.pos + 1 <= length
  - id: data_retries
    type: u1
    if: (present & 0x20000) != 0 and _io.pos + 1 <= length
  - id: pad_xchannel
    size: (4 - _io.pos % 4) % 4
    if: (present & 0x40000) != 0 and (_io.pos + 3) / 4 * 4 + 8 <= length
  - id: xchannel
    size: 8
    if: (present & 0x40000) != 0 and (_io.pos + 3) / 4 * 4 + 8 <= length
  - id: mcs
    size: 3
    if: (present & 0x80000) != 0 and _io.pos + 3 <= length
  - id: pad_ampdu_status
    size: (4 - _io.pos % 4) % 4
    if: (present & 0x100000) != 0 and (_io.pos + 3) / 4 * 4 + 8 <= length
  - id: ampdu_status
    size: 8
    if: (present & 0x100000) != 0 and (_io.pos + 3) / 4 * 4 + 8 <= length
  - id: pad_vht
    size: (2 - _io.pos % 2) % 2
    if: (present & 0x200000) != 0 and (_io.pos + 1) / 2 * 2 + 12 <= length
  - id: vht
    size: 12
    if: (present & 0x200000) != 0 and (_io.pos + 1) / 2 * 2 + 12 <= length
  - id: pad_timestamp
    size: (8 - _io.pos % 8) % 8
    if: (present & 0x400000) != 0 and (_io.pos + 7) / 8 * 8 + 12 <= length
  - id: timestamp
    size: 12
    if: (present & 0x400000) != 0 and (_io.pos + 7) / 8 * 8 + 12 <= length
  - id: pad_he
    size: (2 - _io.pos % 2) % 2
    if: (present & 0x800000) != 0 and (_io.pos + 1) / 2 * 2 + 12 <= length
  - id: he
    size: 12
    if: (present & 0x800000) != 0 and (_io.pos + 1) / 2 * 2 + 12 <= length
  - id: pad_he_mu
    size: (2 - _io.pos % 2) % 2
    if: (present & 0x1000000) != 0 and (_io.pos + 1) / 2 * 2 + 12 <= length
  - id: he_mu
    size: 12
    if: (present & 0x1000000) != 0 and (_io.pos + 1) / 2 * 2 + 12 <= length
  - id: pad_he_mu_other_user
    size: (2 - _io.pos % 2) % 2
    if: (present & 0x2000000) != 0 and (_io.pos + 1) / 2 * 2 + 6 <= length
  - id: he_mu_other_user
    size: 6
    if: (present & 0x2000000) != 0 and (_io.pos + 1) / 2 * 2 + 6 <= length
  - id: zero_length_psdu
    type: u1
    if: (present & 0x4000000) != 0 and _io.pos + 1 <= length
  - id: pad_l_sig
    size: (2 - _io.pos % 2) % 2
    if: (present & 0x8000000) != 0 and (_io.pos + 1) / 2 * 2 + 4 <= length
  - id: l_sig
    size: 4
    if: (present & 0x8000000) != 0 and (_io.pos + 1) / 2 * 2 + 4 <= length
  - id: rest
    size: length - _io.pos
  - id: frame
    type: ieee802_11(fcs_present)
    size-eos: true
instances:
  fcs_present:
    value: (present & 0x2) != 0 and (flags & 0x10) != 0
    doc: |
      True when this header says that the frame ends with a frame check
      sequence (FCS). Many captures include an FCS without setting the flag,
      so false does not prove that the FCS is absent.
