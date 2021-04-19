#include <queue.h>
#include "skel.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Multiplicatori pentru a face adresa IP
const uint32_t FST_OCTET_MULTI = 16777216;
const uint32_t SECOND_OCTET_MULTI = 65536;
const uint32_t THIRD_OCTET_MULTI = 256;

// structura pentru un entry in tabela de rutare
typedef struct {
	uint32_t prefix, hop, msk;
	int interface;
} rTable_entry;

// structura pentru un entry in tabela arp
typedef struct {
	__u32 ip;
	uint8_t mac[6];
} arp_entry;

int rTableLength = 0;
int rTableCapacity = 100;
rTable_entry *tableEntries;

int arpTableLen = 0;
int arpTableCapacity = 100;
arp_entry * arpTable;

// ia ruta cea mai buna pentru un IP
// astfel parcurg tabela de rutare si pentru fiecare entry verific daca
// este un posibil entry valabil pentru acel IP
// raspunsul este NULL (daca nu gaseste niciuna) sau 
// entry-ul cu masca cea mai mare
rTable_entry* getBestRoute(__u32 destIP) {
	rTable_entry *entry = NULL;
	
	for (int i = 0; i < rTableLength; ++i) {
		if ((tableEntries[i].msk & destIP) == tableEntries[i].prefix) {
			 if (entry == NULL) {
				entry = &tableEntries[i];
			 } else if (ntohl(tableEntries[i].msk) > ntohl(entry->msk)) {
				entry = &tableEntries[i];
			 }
		}
	}
	
	return entry;
}

// returneaza entry-ul cu adresa mac specifica IP-ului dat ca parametru
arp_entry* getArpEntry(__u32 ip) {
	for (int i = 0; i < arpTableLen; ++i) {
		if (ip == arpTable[i].ip) {
			return &arpTable[i];
		}
	}

    return NULL;
}

// adauga un nou entry in tabela de arp
void addToARPTable(arp_entry entry) {
	if (arpTableLen == arpTableCapacity) {
		arpTableCapacity *= 2;
		arpTable = realloc(arpTable, sizeof(arp_entry) * arpTableCapacity);
	}

	arpTable[arpTableLen++] = entry;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init(argc - 2, argv + 2);

	FILE *fptr;

	if (argc < 2) {
		fptr = fopen("rtable0.txt", "r");
	} else {
		fptr = fopen(argv[1], "r");
	}

	tableEntries = (rTable_entry *) malloc(sizeof(rTable_entry) *
											rTableCapacity);
	uint32_t prt1, prt2, prt3, prt4;

	// parsarea fisierului de rutare
	// citesc cu fscanf, deoarece imi permite sa citesc dupa un format
	// transformarea este in felul urmator:
	// fiecare adresa sau amsca este citita dupa formatul %d.%d.%d.%d
	// apoi o adresa IP sau masca este formata prin: 
	// prt1 * FST_OCTET_MULTI + prt2 * SECOND_OCTET_MULTI +
	// prt3 * THIRD_OCTET_MULTI + part4, pentru a obtine un INT
	// apoi transmit acest INT lui htonl pentru a-l transforma in 
	// adresa network
	while (fscanf(fptr, "%d.%d.%d.%d", &prt1, &prt2, &prt3, &prt4) != EOF) {
		rTableLength++;

		if (rTableLength == rTableCapacity) {
			rTableCapacity *= 2;
			tableEntries = (rTable_entry *) realloc(tableEntries,
							sizeof(rTable_entry) * rTableCapacity);
		}

		tableEntries[rTableLength - 1].prefix = htonl(prt1 * FST_OCTET_MULTI +
												prt2 * SECOND_OCTET_MULTI +
												prt3 * THIRD_OCTET_MULTI +
												prt4);

		fscanf(fptr, "%d.%d.%d.%d", &prt1, &prt2, &prt3, &prt4);

		tableEntries[rTableLength - 1].hop = htonl(prt1 * FST_OCTET_MULTI +
												prt2 * SECOND_OCTET_MULTI +
												prt3 * THIRD_OCTET_MULTI +
												prt4);

		fscanf(fptr, "%d.%d.%d.%d", &prt1, &prt2, &prt3, &prt4);

		tableEntries[rTableLength - 1].msk = htonl(prt1 * FST_OCTET_MULTI +
												prt2 * SECOND_OCTET_MULTI +
												prt3 * THIRD_OCTET_MULTI +
												prt4);
		
		fscanf(fptr, "%d", &prt1);

		tableEntries[rTableLength - 1].interface = prt1;
	}

	// aloc memoria initiala pt arp_table
	arpTable = (arp_entry *) malloc(arpTableCapacity * sizeof(arp_entry));
	queue q;
	q = queue_create();
	fclose(fptr);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		// extrag headerele arp si icmp din payload-ul packetului
		// cu ajutorul functiilo ajutatoare de parsare
		struct arp_header *arpHdr = parse_arp(m.payload);
		struct icmphdr *icmpHeader = parse_icmp(m.payload);
		// extrag informatiile din payload-ului pachetului
		struct ether_header *ethHdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr*) (m.payload +
								sizeof(struct ether_header));

		// avem un header de tip arp
		// verificam daca este request sau reply
		if (arpHdr != NULL) {
			// la request doar transmit macul interfetei
			if (ntohs(arpHdr->op) == ARPOP_REQUEST) {
				// un nou header ether pentru a nu il pierde pe celalalt
				struct ether_header ethArp;
				
				// completez informatiile acestui header ether
				// adresa mac a destinatiei este sursa de unde a venit
				// requestul ARP
				for (int i = 0; i < 6; ++i) {
					ethArp.ether_dhost[i] = arpHdr->sha[i];
				}

				// este un request de tip ETHERTYPE_ARP
				// macul sursei este macul interfetei pe care a fost trimis
				// packetul
				ethArp.ether_type = htons(ETHERTYPE_ARP);
				get_interface_mac(m.interface, ethArp.ether_shost);
				send_arp(arpHdr->spa, arpHdr->tpa, &ethArp, m.interface,
						htons(ARPOP_REPLY));
			} else { // request ARP de tip reply
				// salvez informatiile necesare, adica adresa mac
				// a IP-ului destinatie
				arp_entry entr;

				// IP-ul este sursa de unde vine request-ul de tip Reply
				entr.ip = arpHdr->spa;
				memcpy(entr.mac, arpHdr->sha, 6);
				addToARPTable(entr);
				
				// coada auxiliara pentru a salva pachetele care nu au
				// destinatia raspunsul dat de acest reply
				queue Q1 = queue_create();

				while (!queue_empty(q)) { // iau fiecare pachet in asteptare
					packet * fromQ = queue_front(q);

					// extrag headerele ether si ip din pachet
					struct ether_header *ethHdr = (struct ether_header *)
													fromQ->payload;
					struct iphdr *ip_hdr = (struct iphdr*) (fromQ->payload +
											sizeof(struct ether_header));

					// verific checksum-ul daca este valid
					// daca nu este il sar ( il arunc )
					if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0) {
						queue_deq(q);
						continue;
					}

					// aflu ruta cea mai buna pentru a transmite acest pachet
					rTable_entry *entry = getBestRoute(ip_hdr->daddr);

					// daca pachetul curent nu trebuie sa ajunga la ipul
					// si adresa mac primita la reply il bag in coada
					// auxiliara si continui cu urmatorul pas
					if (entry->hop != entr.ip) {
						queue_enq(Q1, queue_front(q));
						queue_deq(q);
						continue;
					}

					// decrementez ttl
					ip_hdr->ttl --;

					// fac uptate la checksum
					if (ip_hdr->ttl > 0) {
						ip_hdr->check = 0;
						ip_hdr->check = ip_checksum(ip_hdr,
											sizeof(struct iphdr));
					}

					// schimb tipul pachetului in ETHERTYPE_IP
					// completez cu informatiile necesare
					// adresa mac a destinatiei este macul primit in urma
					// pachetului reply-ului
					ethHdr->ether_type = htons(ETHERTYPE_IP);

					for (int i = 0; i < 6; ++i) {
						ethHdr->ether_dhost[i] = entr.mac[i];
					}

					get_interface_mac(entry->interface, ethHdr->ether_shost);
					send_packet(entry->interface, fromQ);
					queue_deq(q);
				}
				
				// schimb cozile
				// raman cu pachetele neverificate inca
				q = Q1;
			}

			// daca e de tip arp, nu poate fi de alt tip deci trec la next
			// step
			continue;
		}

		// iau ruta cea mai buna a IP-ului destinatie
		rTable_entry *entry = getBestRoute(ip_hdr->daddr);

		// daca nu se afla nimic trimit un pachet ICMP de eroare
		// de tipul DEST_UNREACH, deoarece nu se poate ajunge la
		// destinatie
		// pachetul este trimis inapoi de unde a venit
		if(entry == NULL) {
			send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, ethHdr->ether_dhost,
				ethHdr->ether_shost, ICMP_DEST_UNREACH, 0, m.interface);
			continue;
		}

		// iau adresa mac potrivita rutei
		arp_entry *entr = getArpEntry(entry->hop);

		// daca checksum-ul este gresit, arunc pachetul
		if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0) {
			continue;
		}

		// daca ttl-ul este 1 sau 0 practic se atinge o limita de timp
		// si trimit un pachet ICMP de tip limita de timp la sursa
		// pachetul este de tip eroare
		if (ip_hdr->ttl <= 1) {
			send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, ethHdr->ether_dhost,
				ethHdr->ether_shost, ICMP_TIME_EXCEEDED, 0, m.interface);
			continue;
		}

		// pachetul trimit este de tipul icmpHeader
		if (icmpHeader) {
			// daca este de tip ICMP_ECHOREPLY arunc pachetul
			if (icmpHeader->type == ICMP_ECHOREPLY) {
				continue;
			}

			// daca este de tip ICMP_ECHO trimit un pachet icmp inapoi
			if(icmpHeader->type == ICMP_ECHO) {
				send_icmp(ip_hdr->daddr, ip_hdr->saddr, ethHdr->ether_shost,
					ethHdr->ether_dhost, ICMP_ECHOREPLY, 0, m.interface,
					icmpHeader->un.echo.id, icmpHeader->un.echo.sequence);
				
				// verific daca destinatia este chiar acest router
				// daca este, arunc pachetul
				struct in_addr thisIp;

				inet_aton(get_interface_ip(m.interface), &thisIp);

				if (ip_hdr->daddr == thisIp.s_addr) {
					continue;
				}
			}
		}

		// daca nu gasesc un entry in tabela ARP, atunci trebuie
		// sa fac un arp request si sa aflu adresa mac pentru
		// IP-ul respectiv
		if (entr == NULL) {
			packet *pkg = (packet*)malloc(sizeof(packet));
			struct in_addr sendFrom;

			// copiez pachetul pentru  a nu avea probleme cu memoria
			memcpy(pkg, &m, sizeof(packet));
			// bag pachetul in coada
			// momentan nu stiu unde trebuie sa ajunga, deci il salvez
			// pentru a il redirectiona mai tarziu
			queue_enq(q, pkg);
			
			// creez in header ether si il completez cu informatiile necesare
			// adresa mac a sursei este adresa interfetei
			// adresa mac a destinatiei este 255.255.255.255, pentru a lua
			// in considerare orice nod din reteaua de internet, 
			// pachetele ARP fiind trimise global
			struct ether_header * etARP = malloc(sizeof(struct ether_header));

			etARP->ether_type = htons(ETHERTYPE_ARP);
			get_interface_mac(entry->interface, etARP->ether_shost);
			inet_aton(get_interface_ip(entry->interface), &sendFrom);

			for (int i = 0; i < 6; ++i) {
				etARP->ether_dhost[i] = (uint8_t) 255;
			}
			
			// trimit pachetul de tip ARP REQUEST
			send_arp(entry->hop, sendFrom.s_addr, etARP, entry->interface,
					htons(ARPOP_REQUEST));
			continue;
		}

		// in orice alt caz am un pachet normal care trebuie directionat
		// decrementez ttl
		ip_hdr->ttl --;

		// fac update la checksum
		if (ip_hdr->ttl > 0) {
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
		}

		// completez headerul ether
		for (int i = 0; i < 6; ++i) {
			ethHdr->ether_dhost[i] = entr->mac[i];
		}

		get_interface_mac(entry->interface, ethHdr->ether_shost);
		ethHdr->ether_type = htons(ETHERTYPE_IP);

		// trimit pachetul mai departe
		send_packet(entry->interface, &m);
	}

	return 0;
}