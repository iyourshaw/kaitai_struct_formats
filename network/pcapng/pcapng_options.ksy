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
  id: pcapng_options
  title: pcapng block options
  license: Apache-2.0
  ks-version: '0.11'
  endian:
    switch-on: is_le
    cases:
      true: le
      false: be
doc: |
  The options at the end of a pcapng block. Each option is a code, a length,
  a value and padding to 4 bytes. A list ends at an end-of-options option or
  at the end of the block, because writers can leave out the end-of-options
  option.

  What an option code means depends on the kind of block it's in: code 2 is
  the hardware name in a Section Header Block and the interface name in an
  Interface Description Block. A few codes mean the same in every block: the
  comment and the custom options. So each option's value is parsed in two
  steps: `value_kind` picks the common codes or the block's kind, and the
  `*_option_value` type for that kind maps the code to its value type.
doc-ref: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
params:
  - id: is_le
    type: bool
    doc: True if the section is little-endian.
  - id: kind
    type: u1
    enum: option_kind
    doc: The kind of block these options belong to.
seq:
  - id: entries
    type: option
    if: not _io.eof
    repeat: until
    repeat-until: _.code == 0 or _io.eof
types:
  option:
    doc: |
      A single option. When a value has the wrong length for its type, the
      fixed-size fields of that type stay unset and parsing continues, so the
      options after it are still read. A missing field marks such a value, and
      the spec says that readers should report it.
    seq:
      - id: code
        type: u2
        doc: |
          The option code. It is a plain integer, so that unknown codes keep
          their number; `value.code` names it.
      - id: len_value
        type: u2
      - id: value
        size: len_value
        type:
          switch-on: value_kind
          cases:
            'option_kind::common': common_option_value
            'option_kind::section_header': section_header_option_value
            'option_kind::interface_description': interface_description_option_value
            'option_kind::enhanced_packet': enhanced_packet_option_value
            'option_kind::packet': packet_option_value
            'option_kind::name_resolution': name_resolution_option_value
            'option_kind::interface_statistics': interface_statistics_option_value
      - id: padding
        size: (4 - len_value % 4) % 4
    instances:
      value_kind:
        doc: |
          `common` for the codes that mean the same in every block (comment
          and custom options), otherwise the kind of block.
        value: >-
          code == 1 or code == 2988 or code == 2989 or code == 19372 or code == 19373
          ? option_kind::common : _parent.kind

  # One type per kind of block: each names its codes and maps them to a value
  # type. Codes not listed stay raw bytes.
  common_option_value:
    seq:
      - id: value
        size-eos: true
        type:
          switch-on: code
          cases:
            'common_option_code::opt_comment': option_text
            'common_option_code::opt_custom_text': custom_option_text
            'common_option_code::opt_custom_text_no_copy': custom_option_text
            'common_option_code::opt_custom_bytes': custom_option_bytes
            'common_option_code::opt_custom_bytes_no_copy': custom_option_bytes
    instances:
      code:
        value: _parent.code
        enum: common_option_code
  section_header_option_value:
    seq:
      - id: value
        size-eos: true
        type:
          switch-on: code
          cases:
            'section_header_option_code::shb_hardware': option_text
            'section_header_option_code::shb_os': option_text
            'section_header_option_code::shb_userappl': option_text
    instances:
      code:
        value: _parent.code
        enum: section_header_option_code
  interface_description_option_value:
    seq:
      - id: value
        size-eos: true
        type:
          switch-on: code
          cases:
            'interface_description_option_code::if_name': option_text
            'interface_description_option_code::if_description': option_text
            'interface_description_option_code::if_ipv4addr': option_ipv4_with_netmask
            'interface_description_option_code::if_ipv6addr': option_ipv6_with_prefix
            'interface_description_option_code::if_macaddr': option_eui48
            'interface_description_option_code::if_euiaddr': option_eui64
            'interface_description_option_code::if_speed': option_u8
            'interface_description_option_code::if_tsresol': option_u1
            'interface_description_option_code::if_tzone': option_u4
            'interface_description_option_code::if_filter': option_with_kind
            'interface_description_option_code::if_os': option_text
            'interface_description_option_code::if_fcslen': option_u1
            'interface_description_option_code::if_tsoffset': option_s8
            'interface_description_option_code::if_hardware': option_text
            'interface_description_option_code::if_txspeed': option_u8
            'interface_description_option_code::if_rxspeed': option_u8
            'interface_description_option_code::if_iana_tzname': option_text
    instances:
      code:
        value: _parent.code
        enum: interface_description_option_code
  enhanced_packet_option_value:
    seq:
      - id: value
        size-eos: true
        type:
          switch-on: code
          cases:
            'enhanced_packet_option_code::epb_flags': option_u4
            'enhanced_packet_option_code::epb_hash': option_with_kind
            'enhanced_packet_option_code::epb_dropcount': option_u8
            'enhanced_packet_option_code::epb_packetid': option_u8
            'enhanced_packet_option_code::epb_queue': option_u4
            'enhanced_packet_option_code::epb_verdict': option_with_kind
            'enhanced_packet_option_code::epb_processid_threadid': option_process_thread
    instances:
      code:
        value: _parent.code
        enum: enhanced_packet_option_code
  packet_option_value:
    seq:
      - id: value
        size-eos: true
        type:
          switch-on: code
          cases:
            'packet_option_code::pack_flags': option_u4
            'packet_option_code::pack_hash': option_with_kind
    instances:
      code:
        value: _parent.code
        enum: packet_option_code
  name_resolution_option_value:
    seq:
      - id: value
        size-eos: true
        type:
          switch-on: code
          cases:
            'name_resolution_option_code::ns_dnsname': option_text
            'name_resolution_option_code::ns_dnsip4addr': option_ipv4
            'name_resolution_option_code::ns_dnsip6addr': option_ipv6
    instances:
      code:
        value: _parent.code
        enum: name_resolution_option_code
  interface_statistics_option_value:
    seq:
      - id: value
        size-eos: true
        type:
          switch-on: code
          cases:
            'interface_statistics_option_code::isb_starttime': option_timestamp
            'interface_statistics_option_code::isb_endtime': option_timestamp
            'interface_statistics_option_code::isb_ifrecv': option_u8
            'interface_statistics_option_code::isb_ifdrop': option_u8
            'interface_statistics_option_code::isb_filteraccept': option_u8
            'interface_statistics_option_code::isb_osdrop': option_u8
            'interface_statistics_option_code::isb_usrdeliv': option_u8
    instances:
      code:
        value: _parent.code
        enum: interface_statistics_option_code

  # The value types.
  option_text:
    doc: |
      A text value. Writers do not always zero-terminate it, but a zero byte
      ends it when one is present. Writers do not always produce valid UTF-8
      either.
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
        doc: The IANA Private Enterprise Number of the organization that defined the option.
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
        doc: The IANA Private Enterprise Number of the organization that defined the option.
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
      The value of a filter, hash or verdict option. Its first byte gives the
      kind of value, which determines how to read the rest.
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
