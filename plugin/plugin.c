#include <epan/packet.h>


// https://www.wireshark.org/docs/wsdg_html_chunked/ChDissectAdd.html

#define FOO_PORT 1234

static int proto_foo;

static dissector_handle_t foo_handle;

static void dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_){
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FOO");
        /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    return tvb_captured_length(tvb);
    // extract packets here : No.,Time,Source,Destination,Protocol,Length,Info
}

void proto_register_foo(void){

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

void proto_reg_handoff_foo(void){
    dissector_add_uint("udp.port", FOO_PORT, foo_handle);
}