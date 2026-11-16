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
  id: pcapng_section_header_block
  title: pcapng Section Header Block
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
  The body of a Section Header Block, the first block of every section. Its
  byte-order magic tells readers the section's byte order; `pcapng` reads the
  magic ahead to choose it.
doc-ref: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
params:
  - id: is_le
    type: bool
    doc: |
      True if the section is little-endian. `pcapng` passes the section's
      byte order, which a type in another file can't inherit.
seq:
  - id: byte_order_magic
    type: u4
    valid: 0x1a2b3c4d
  - id: version_major
    type: u2
  - id: version_minor
    type: u2
    doc: Some writers wrote 2 here. Readers treat it as 0.
  - id: section_length
    type: s8
    doc: |
      The size in bytes of the rest of the section after this block, or -1
      when the writer did not record it.
  - id: options
    type: pcapng_options(is_le, pcapng_options::option_kind::section_header)
