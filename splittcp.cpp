
#include <iostream>
#include <tins/tins.h>

using namespace std;
using namespace Tins;

const size_t LIMIT = 1400;

int main(const int c, const char **v) {
    if (c < 3) {
        cout << "Usage: " << v[0] << "input.pcap output.pcap" << endl;
        return 1;
    }
    FileSniffer reader(v[1]);
    PacketWriter writer(v[2], DataLinkType<EthernetII>());
    for (auto &packet : reader) {
        if (!packet.pdu()->find_pdu<EthernetII>()) {
            continue;
        }
        if (packet.pdu()->size() > LIMIT) {
            TCP *tcp = packet.pdu()->find_pdu<TCP>();
            if (tcp) {
                uint32_t seq = tcp->seq();
                RawPDU *raw = static_cast<RawPDU *>(tcp->release_inner_pdu());
                auto from = raw->payload().begin();
                auto to = raw->payload().begin() + LIMIT;
                while (to < raw->payload().end()) {
                    RawPDU chunk(from, to);
                    tcp->inner_pdu(chunk);
                    tcp->seq(seq);
                    seq += LIMIT;
                    writer.write(packet);
                    from += LIMIT;
                    to = from + LIMIT;
                }
                RawPDU chunk(from, raw->payload().end());
                tcp->inner_pdu(chunk);
                tcp->seq(seq);
                writer.write(packet);
                delete raw;
                continue;
            }
        }
        writer.write(packet);
    }
    return 0;
}
