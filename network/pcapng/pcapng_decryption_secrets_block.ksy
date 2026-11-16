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
  id: pcapng_decryption_secrets_block
  title: pcapng Decryption Secrets Block
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
  The body of a Decryption Secrets Block: keys or key logs (TLS, SSH, WireGuard,
  ...) that let a reader decrypt traffic in the capture.
doc-ref: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
params:
  - id: is_le
    type: bool
    doc: |
      True if the section is little-endian. `pcapng` passes the section's
      byte order, which a type in another file can't inherit.
seq:
  - id: secrets_type
    type: u4
    enum: secrets_type_enum
  - id: len_secrets
    type: u4
  - id: secrets
    size: len_secrets
  - id: padding
    size: (4 - len_secrets % 4) % 4
  - id: options
    type: pcapng_options(is_le, pcapng_options::option_kind::common)
enums:
  # Named *_enum so it can't clash with the field `secrets_type` (C# CS0102).
  secrets_type_enum:
    0x45535053: esp_keys
    0x5353484b: ssh_key_log
    0x544c534b: tls_key_log
    0x55414b4c: opc_ua_key_log
    0x57474b4c: wireguard_key_log
    0x5a415053: zigbee_aps_key
    0x5a4e574b: zigbee_nwk_key
