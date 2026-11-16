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
  id: pcapng_name_resolution_block
  title: pcapng Name Resolution Block
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
  The body of a Name Resolution Block: a list of records that map addresses
  (IPv4, IPv6, EUI-48, EUI-64) to names, ending with an end-of-records record.
doc-ref: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
params:
  - id: is_le
    type: bool
    doc: |
      True if the section is little-endian. `pcapng` passes the section's
      byte order, which a type in another file can't inherit.
seq:
  - id: records
    type: name_record
    repeat: until
    repeat-until: _.record_type == 0
  - id: options
    type: pcapng_options(is_le, pcapng_options::option_kind::name_resolution)
types:
  name_record:
    seq:
      - id: record_type
        type: u2
        doc: |
          A value from the `name_record_type` enum. The field is a plain
          integer so that unknown record types keep their number. Readers
          must skip records of unknown types.
      - id: len_value
        type: u2
      - id: value
        size: len_value
        type:
          switch-on: record_type
          cases:
            1: named_address(4)
            2: named_address(16)
            3: named_address(6)
            4: named_address(8)
      - id: padding
        size: (4 - len_value % 4) % 4
  named_address:
    params:
      - id: len_address
        type: u1
    seq:
      - id: address
        size: len_address
      - id: names
        type: strz
        encoding: UTF-8
        eos-error: false
        repeat: eos
enums:
  name_record_type:
    0: end_of_records
    1: ipv4
    2: ipv6
    3: eui48
    4: eui64
