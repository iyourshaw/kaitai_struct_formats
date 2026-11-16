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
  id: pcapng
  title: PCAP Now Generic capture file
  file-extension: pcapng
  license: Apache-2.0
  ks-version: '0.11'
  imports:
    - /network/pcapng/pcapng_section_header_block
    - /network/pcapng/pcapng_interface_description_block
    - /network/pcapng/pcapng_enhanced_packet_block
    - /network/pcapng/pcapng_simple_packet_block
    - /network/pcapng/pcapng_packet_block
    - /network/pcapng/pcapng_name_resolution_block
    - /network/pcapng/pcapng_interface_statistics_block
    - /network/pcapng/pcapng_decryption_secrets_block
    - /network/pcapng/pcapng_custom_block
doc: |
  A pcapng file is a sequence of sections. Each section starts with a Section
  Header Block and holds every block up to the next Section Header Block. Each
  section declares its own byte order, so one file can contain both
  little-endian and big-endian sections.

  This file holds the framing: sections, and the blocks in them. Every block
  has the same framing (a type, a total length, a body, and the total length
  again). The body of each block type is described in its own file
  (`pcapng_enhanced_packet_block` and so on), and the options that most blocks
  end with are described in `pcapng_options`. Each of those files takes the
  section's byte order as the parameter `is_le`.

  This spec leaves packet data as raw bytes. The link type of a packet is set
  by an Interface Description Block earlier in the same section, and a Kaitai
  Struct expression cannot look up that block. To parse packet data, pass it
  to `pcapng_link_frame` with the link type of its interface.
doc-ref: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
seq:
  - id: sections
    type: section_in_file
    repeat: eos
types:
  section_in_file:
    doc: |
      A wrapper that reads the byte-order magic ahead of the section. The
      section's endianness depends on the magic, and Kaitai Struct cannot read
      a field of a type until it knows that type's endianness.
    seq:
      - id: section
        type: section
    instances:
      byte_order_magic:
        doc: |
          The byte-order magic of the Section Header Block. It starts 8 bytes
          into the section in either byte order, and it is compared as raw
          bytes.
        pos: _io.pos + 8
        size: 4
  section:
    meta:
      endian:
        switch-on: _parent.byte_order_magic
        cases:
          '[0x4d, 0x3c, 0x2b, 0x1a]': le
          '[0x1a, 0x2b, 0x3c, 0x4d]': be
    seq:
      - id: header
        type: block
      - id: blocks
        type: block
        if: is_supported_version and not header.ends_section
        repeat: until
        repeat-until: _.ends_section
      - id: skipped_blocks
        doc: |
          The blocks of a section whose version this spec does not support.
          Block formats can change between versions, but every block starts
          with its type and length and ends with the length again. A reader
          can therefore step over blocks that it cannot parse.
        type: skipped_block
        if: not is_supported_version and not header.ends_section
        repeat: until
        repeat-until: _.ends_section
    instances:
      is_le:
        doc: |
          True for a little-endian section. The block bodies are in other
          files, which can't inherit this section's byte order, so each block
          passes it to its body.
        value: _parent.byte_order_magic == [0x4d, 0x3c, 0x2b, 0x1a]
      is_supported_version:
        doc: |
          True for versions 1.0 and 1.2. Some writers wrote minor version 2,
          and readers treat it as 1.0.
        value: >-
          header.body.as<pcapng_section_header_block>.version_major == 1
          and (header.body.as<pcapng_section_header_block>.version_minor == 0
          or header.body.as<pcapng_section_header_block>.version_minor == 2)
    types:
      block:
        doc: |
          A block of any type. Every block has the same framing: a type, a
          total length, a body, and the total length again. A reader skips
          unknown blocks and options by their lengths, which is what lets the
          format grow without breaking old readers.
        seq:
          - id: block_type
            type: u4
            enum: block_type
          - id: len_block
            type: u4
            doc: |
              The size of the whole block in bytes, including the type and
              length fields. It is a multiple of 4.
          - id: body
            size: len_block - 12
            type:
              switch-on: block_type
              cases:
                'block_type::section_header': pcapng_section_header_block(_parent.is_le)
                'block_type::interface_description': pcapng_interface_description_block(_parent.is_le)
                'block_type::enhanced_packet': pcapng_enhanced_packet_block(_parent.is_le)
                'block_type::simple_packet': pcapng_simple_packet_block(_parent.is_le)
                'block_type::packet': pcapng_packet_block(_parent.is_le)
                'block_type::name_resolution': pcapng_name_resolution_block(_parent.is_le)
                'block_type::interface_statistics': pcapng_interface_statistics_block(_parent.is_le)
                'block_type::decryption_secrets': pcapng_decryption_secrets_block(_parent.is_le)
                'block_type::custom_copied': pcapng_custom_block(_parent.is_le)
                'block_type::custom_not_copied': pcapng_custom_block(_parent.is_le)
          - id: len_block_trailing
            type: u4
            valid: len_block
        instances:
          next_block_type:
            doc: |
              The type of the next block. It is read right after this block,
              when the stream position is at the start of the next one.
            if: not _io.eof
            pos: _io.pos
            size: 4
          ends_section:
            doc: |
              True when this block is the last one in its section. A section
              has no end marker, so it ends at the end of the file or at the
              next Section Header Block.
            value: _io.eof or next_block_type == [0x0a, 0x0d, 0x0d, 0x0a]
      skipped_block:
        doc: |
          A block in a section of an unsupported version: only its framing is
          read.
        seq:
          - id: block_type
            type: u4
          - id: len_block
            type: u4
          - id: body
            size: len_block - 12
          - id: len_block_trailing
            type: u4
            valid: len_block
        instances:
          next_block_type:
            if: not _io.eof
            pos: _io.pos
            size: 4
          ends_section:
            value: _io.eof or next_block_type == [0x0a, 0x0d, 0x0d, 0x0a]
enums:
  block_type:
    # Block types from the draft's registry. Types without a body type above
    # are kept as raw bytes.
    0x00000001: interface_description
    0x00000002: packet
    0x00000003: simple_packet
    0x00000004: name_resolution
    0x00000005: interface_statistics
    0x00000006: enhanced_packet
    0x00000007: irig_timestamp
    0x00000008: arinc_429_afdx
    0x00000009: systemd_journal_export
    0x0000000a: decryption_secrets
    0x00000101: hone_machine_info
    0x00000102: hone_connection_info
    0x00000201: sysdig_machine_info
    0x00000202: sysdig_process_info_v1
    0x00000203: sysdig_fd_list
    0x00000204: sysdig_event
    0x00000205: sysdig_interface_list
    0x00000206: sysdig_user_list
    0x00000207: sysdig_process_info_v2
    0x00000208: sysdig_event_with_flags
    0x00000209: sysdig_process_info_v3
    0x00000210: sysdig_process_info_v4
    0x00000211: sysdig_process_info_v5
    0x00000212: sysdig_process_info_v6
    0x00000213: sysdig_process_info_v7
    0x00000bad: custom_copied
    0x0a0d0d0a: section_header
    0x40000bad: custom_not_copied
