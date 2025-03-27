#include "config.h"
#include <epan/packet.h>

#define FOO_PORT 1234
#define FOO_START_FLAG      0x01
#define FOO_END_FLAG        0x02
#define FOO_PRIORITY_FLAG   0x04

static int proto_foo;

static dissector_handle_t foo_handle;

static int hf_foo_pdu_type;
static int ett_foo;

static int hf_foo_flags;
static int hf_foo_sequenceno;
static int hf_foo_initialip;

static int hf_foo_startflag;
static int hf_foo_endflag;
static int hf_foo_priorityflag;


// Naming the packet types. 
static const value_string packettypenames[] ={
    { 1, "Init" },
    { 2, "Terminate" },
    { 3, "Data" },
    { 4, NULL }
};

static int dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    int offset = 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FOO");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Type %s", val_to_str(packet_type, packettypenames, "Unknown (0x%02x)"));

    static int* const bits[] = {
        &hf_foo_startflag,
        &hf_foo_endflag,
        &hf_foo_priorityflag,
        NULL
    };



    proto_item *ti = proto_tree_add_item(tree, proto_foo, tvb, 0, -1, ENC_NA);
    proto_item_append_text(ti, ", Type %s", val_to_str(packet_type, packettypenames, "Unknown (0x%02x)"));
    proto_tree *foo_tree = proto_item_add_subtree(ti, ett_foo);
    proto_tree_add_item(foo_tree, hf_foo_pdu_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(foo_tree, hf_foo_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(foo_tree, hf_foo_sequenceno, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(foo_tree, hf_foo_initialip, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_bitmask(foo_tree, tvb, offset, hf_foo_flags, ett_foo, bits, ENC_BIG_ENDIAN);
    offset += 1;
   

    return tvb_captured_length(tvb);
}

void proto_register_foo(void)
{

    /*
        hf_foo_pdu_type - The node’s index.
        FOO PDU Type - The item’s label, as it will appear in the protocol tree.
        foo.type - The item’s abbreviated name, for use in the display filter (e.g., foo.type==1).
        FT_UINT8 - The item’s type: An 8bit unsigned integer. This tallies with our call above where we tell it to only look at one byte.
        BASE_DEC - For an integer type, this tells it to be printed as a decimal number. It could be hexadecimal (BASE_HEX) or octal (BASE_OCT) if that made more sense.
    */
    static hf_register_info hf[] = {
        { &hf_foo_pdu_type,
            { "FOO PDU Type", "foo.type",
            FT_UINT8, BASE_DEC,
            VALS(packettypenames), 0x0,
            NULL, HFILL }
        },
        { &hf_foo_flags,
            { "FOO PDU Flags", "foo.flags",
            FT_UINT8, BASE_HEX,
            VALS(packettypenames), 0x0,
            NULL, HFILL }
        },
        { &hf_foo_sequenceno,
            { "FOO PDU Sequence Number", "foo.seqn",
            FT_UINT16, BASE_DEC,
            VALS(packettypenames), 0x0,
            NULL, HFILL }
        },
        { &hf_foo_initialip,
            { "FOO PDU Initial IP", "foo.initialip",
            FT_IPv4, BASE_NONE,
            VALS(packettypenames), 0x0,
            NULL, HFILL }
        },
        { &hf_foo_startflag,
            { "FOO PDU Start Flags", "foo.flags.start",
            FT_BOOLEAN, 8,
            NULL, FOO_START_FLAG,
            NULL, HFILL }
        },
        { &hf_foo_endflag,
            { "FOO PDU End Flags", "foo.flags.end",
            FT_BOOLEAN, 8,
            NULL, FOO_END_FLAG,
            NULL, HFILL }
        },
        { &hf_foo_priorityflag,
            { "FOO PDU Priority Flags", "foo.flags.priority",
            FT_BOOLEAN, 8,
            NULL, FOO_PRIORITY_FLAG,
            NULL, HFILL }
        },
    };

    /* setup protocol subtree array */
    static int *ett[]={
        &ett_foo
    };

    proto_foo = proto_register_protocol (
        "FOO Protocol", /* protocol name        */
        "FOO",          /* protocol short name  */
        "foo"           /* protocol filter_name */
        );

    foo_handle = register_dissector_with_description (
        "foo",          /* dissector name           */
        "Foo Protocol", /* dissector description    */
        dissect_foo,    /* dissector function       */
        proto_foo       /* protocol being dissected */
        );
}

void proto_reg_handoff_foo(void)
{
    dissector_add_uint("udp.port", FOO_PORT, foo_handle);
}