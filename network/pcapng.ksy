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
  imports:
    - /network/pcap
doc: |
  A pcapng file is a sequence of sections. Each section starts with a Section
  Header Block and holds every block up to the next Section Header Block. Each
  section declares its own byte order, so one file can contain both
  little-endian and big-endian sections.

  This spec leaves packet data as raw bytes. The link type of a packet is set
  by an Interface Description Block earlier in the same section, and a Kaitai
  Struct expression cannot look up that block. To parse packet data, pass it
  to `link_frame` with the link type of its interface.
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
      is_supported_version:
        doc: |
          True for versions 1.0 and 1.2. Some writers wrote minor version 2,
          and readers treat it as 1.0.
        value: >-
          header.body.as<section_header_block>.version_major == 1
          and (header.body.as<section_header_block>.version_minor == 0
          or header.body.as<section_header_block>.version_minor == 2)
    types:
      skipped_block:
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
                'block_type::section_header': section_header_block
                'block_type::interface_description': interface_description_block
                'block_type::packet': packet_block
                'block_type::simple_packet': simple_packet_block
                'block_type::name_resolution': name_resolution_block
                'block_type::interface_statistics': interface_statistics_block
                'block_type::enhanced_packet': enhanced_packet_block
                'block_type::decryption_secrets': decryption_secrets_block
                'block_type::custom_copied': custom_block
                'block_type::custom_not_copied': custom_block
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
      section_header_block:
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
              The size in bytes of the rest of the section after this block,
              or -1 when the writer did not record it.
          - id: options
            type: options(option_kind::section_header)
      interface_description_block:
        seq:
          - id: link_type
            type: u2
            enum: pcap::linktype
          - id: reserved
            size: 2
          - id: snaplen
            type: u4
            doc: |
              The maximum number of bytes captured from each packet. A value
              of 0 means there is no limit.
          - id: options
            type: options(option_kind::interface_description)
      enhanced_packet_block:
        seq:
          - id: interface_id
            type: u4
          - id: ts_high
            type: u4
            doc: |
              The upper 32 bits of the timestamp. `ts_low` holds the lower 32
              bits. The timestamp counts units of time since an epoch, and the
              interface's `if_tsresol` and `if_tsoffset` options define the
              unit and the epoch.
          - id: ts_low
            type: u4
          - id: len_packet_data
            type: u4
          - id: len_original
            type: u4
          - id: packet_data
            size: len_packet_data
          - id: padding
            size: (4 - len_packet_data % 4) % 4
          - id: options
            type: options(option_kind::enhanced_packet)
      simple_packet_block:
        seq:
          - id: len_original
            type: u4
          - id: packet_data_and_padding
            size-eos: true
            doc: |
              The packet data followed by padding. The length of the packet
              data is the smallest of `len_original`, the size of this field,
              and the snaplen of the section's first interface. A snaplen of
              0 is left out of the comparison.
      packet_block:
        doc: |
          The obsolete Packet Block. Writers must not write it, but readers
          can find it in old files.
        seq:
          - id: interface_id
            type: u2
          - id: drops_count
            type: u2
          - id: ts_high
            type: u4
          - id: ts_low
            type: u4
          - id: len_packet_data
            type: u4
          - id: len_original
            type: u4
          - id: packet_data
            size: len_packet_data
          - id: padding
            size: (4 - len_packet_data % 4) % 4
          - id: options
            type: options(option_kind::packet)
      name_resolution_block:
        seq:
          - id: records
            type: name_record
            repeat: until
            repeat-until: _.record_type == 0
          - id: options
            type: options(option_kind::name_resolution)
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
      interface_statistics_block:
        seq:
          - id: interface_id
            type: u4
          - id: ts_high
            type: u4
          - id: ts_low
            type: u4
          - id: options
            type: options(option_kind::interface_statistics)
      decryption_secrets_block:
        seq:
          - id: secrets_type
            type: u4
            enum: secrets_type
          - id: len_secrets
            type: u4
          - id: secrets
            size: len_secrets
          - id: padding
            size: (4 - len_secrets % 4) % 4
          - id: options
            type: options(option_kind::common)
      custom_block:
        doc: |
          A block defined by a vendor. Options can follow the custom data, but
          only the vendor knows where the data ends, so `custom_data` holds
          both.
        seq:
          - id: pen
            type: u4
            doc: |
              The IANA Private Enterprise Number of the organization that
              defined this block.
          - id: custom_data
            size-eos: true
      options:
        doc: |
          A list of options. It ends at an end-of-options option or at the end
          of the block, because writers can leave out the end-of-options
          option.
        params:
          - id: kind
            type: u1
            enum: option_kind
        seq:
          - id: entries
            type: option(kind)
            if: not _io.eof
            repeat: until
            repeat-until: _.code == 0 or _io.eof
      option:
        doc: |
          A single option. When a value has the wrong length for its type, the
          fixed-size fields of that type stay unset and parsing continues, so
          the options after it are still read. A missing field marks such a
          value, and the spec says that readers should report it.
        params:
          - id: kind
            type: u1
            enum: option_kind
        seq:
          - id: code
            type: u2
          - id: len_value
            type: u2
          - id: value
            size: len_value
            type:
              # See value_key. Keys above 0xffff hold the option kind in the
              # upper 16 bits and the option code in the lower 16 bits.
              switch-on: value_key
              cases:
                1: option_text
                2988: custom_option_text
                19372: custom_option_text
                2989: custom_option_bytes
                19373: custom_option_bytes
                0x10002: option_text
                0x10003: option_text
                0x10004: option_text
                0x20002: option_text
                0x20003: option_text
                0x20004: option_ipv4_with_netmask
                0x20005: option_ipv6_with_prefix
                0x20006: option_eui48
                0x20007: option_eui64
                0x20008: option_u8
                0x20009: option_u1
                0x2000a: option_u4
                0x2000b: option_with_kind
                0x2000c: option_text
                0x2000d: option_u1
                0x2000e: option_s8
                0x2000f: option_text
                0x20010: option_u8
                0x20011: option_u8
                0x20012: option_text
                0x30002: option_u4
                0x30003: option_with_kind
                0x30004: option_u8
                0x30005: option_u8
                0x30006: option_u4
                0x30007: option_with_kind
                0x30008: option_process_thread
                0x40002: option_u4
                0x40003: option_with_kind
                0x50002: option_text
                0x50003: option_ipv4
                0x50004: option_ipv6
                0x60002: option_timestamp
                0x60003: option_timestamp
                0x60004: option_u8
                0x60005: option_u8
                0x60006: option_u8
                0x60007: option_u8
                0x60008: option_u8
          - id: padding
            size: (4 - len_value % 4) % 4
        instances:
          value_key:
            doc: |
              The key that selects the type of `value`. Comment and custom
              option codes mean the same in every block, so the key is the
              code itself. Other codes depend on the kind of block, so the key
              combines the option kind with the code.
            value: >-
              code == 1 or code == 2988 or code == 2989 or code == 19372 or code == 19373
              ? code : kind.to_i * 0x10000 + code
      option_text:
        doc: |
          A text value. Writers do not always zero-terminate it, but a zero
          byte ends it when one is present. Writers do not always produce
          valid UTF-8 either.
        seq:
          - id: value
            type: str
            size-eos: true
            terminator: 0
            encoding: UTF-8
      custom_option_text:
        seq:
          - id: pen
            type: u4
            if: _io.size >= 4
          - id: value
            type: str
            size-eos: true
            terminator: 0
            encoding: UTF-8
      custom_option_bytes:
        seq:
          - id: pen
            type: u4
            if: _io.size >= 4
          - id: data
            size-eos: true
      option_u1:
        seq:
          - id: value
            type: u1
            if: _io.size == 1
      option_u4:
        seq:
          - id: value
            type: u4
            if: _io.size == 4
      option_u8:
        seq:
          - id: value
            type: u8
            if: _io.size == 8
      option_s8:
        seq:
          - id: value
            type: s8
            if: _io.size == 8
      option_ipv4:
        seq:
          - id: address
            size: 4
            if: _io.size == 4
      option_ipv6:
        seq:
          - id: address
            size: 16
            if: _io.size == 16
      option_ipv4_with_netmask:
        seq:
          - id: address
            size: 4
            if: _io.size == 8
          - id: netmask
            size: 4
            if: _io.size == 8
      option_ipv6_with_prefix:
        seq:
          - id: address
            size: 16
            if: _io.size == 17
          - id: prefix_length
            type: u1
            if: _io.size == 17
      option_eui48:
        seq:
          - id: address
            size: 6
            if: _io.size == 6
      option_eui64:
        seq:
          - id: address
            size: 8
            if: _io.size == 8
      option_with_kind:
        doc: |
          The value of a filter, hash or verdict option. Its first byte gives
          the kind of value, which determines how to read the rest.
        seq:
          - id: value_kind
            type: u1
            if: _io.size >= 1
          - id: data
            size-eos: true
      option_process_thread:
        seq:
          - id: process_id
            type: u4
            if: _io.size == 8
          - id: thread_id
            type: u4
            if: _io.size == 8
      option_timestamp:
        seq:
          - id: ts_high
            type: u4
            if: _io.size == 8
          - id: ts_low
            type: u4
            if: _io.size == 8
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
  name_record_type:
    0: end
    1: ipv4
    2: ipv6
    3: eui48
    4: eui64
  secrets_type:
    0x45535053: esp_keys
    0x5353484b: ssh_key_log
    0x544c534b: tls_key_log
    0x55414b4c: opc_ua_key_log
    0x57474b4c: wireguard_key_log
    0x5a415053: zigbee_aps_key
    0x5a4e574b: zigbee_nwk_key
  option_kind:
    0: common
    1: section_header
    2: interface_description
    3: enhanced_packet
    4: packet
    5: name_resolution
    6: interface_statistics
  common_option_code:
    0: opt_endofopt
    1: opt_comment
    2988: opt_custom_text
    2989: opt_custom_bytes
    19372: opt_custom_text_no_copy
    19373: opt_custom_bytes_no_copy
  section_header_option_code:
    2: shb_hardware
    3: shb_os
    4: shb_userappl
  interface_description_option_code:
    2: if_name
    3: if_description
    4: if_ipv4addr
    5: if_ipv6addr
    6: if_macaddr
    7: if_euiaddr
    8: if_speed
    9: if_tsresol
    10: if_tzone
    11: if_filter
    12: if_os
    13: if_fcslen
    14: if_tsoffset
    15: if_hardware
    16: if_txspeed
    17: if_rxspeed
    18: if_iana_tzname
  enhanced_packet_option_code:
    2: epb_flags
    3: epb_hash
    4: epb_dropcount
    5: epb_packetid
    6: epb_queue
    7: epb_verdict
    8: epb_processid_threadid
  packet_option_code:
    2: pack_flags
    3: pack_hash
  name_resolution_option_code:
    2: ns_dnsname
    3: ns_dnsip4addr
    4: ns_dnsip6addr
  interface_statistics_option_code:
    2: isb_starttime
    3: isb_endtime
    4: isb_ifrecv
    5: isb_ifdrop
    6: isb_filteraccept
    7: isb_osdrop
    8: isb_usrdeliv
