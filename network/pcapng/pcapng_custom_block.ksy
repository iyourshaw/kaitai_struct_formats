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
  id: pcapng_custom_block
  title: pcapng Custom Block
  license: Apache-2.0
  ks-version: '0.11'
  endian:
    switch-on: is_le
    cases:
      true: le
      false: be
doc: |
  The body of a Custom Block, defined by a vendor. Options can follow the custom
  data, but only the vendor knows where the data ends, so `custom_data` holds
  both.
doc-ref: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
params:
  - id: is_le
    type: bool
    doc: |
      True if the section is little-endian. `pcapng` passes the section's
      byte order, which a type in another file can't inherit.
seq:
  - id: pen
    type: u4
    doc: |
      The IANA Private Enterprise Number of the organization that defined this
      block.
  - id: custom_data
    size-eos: true
