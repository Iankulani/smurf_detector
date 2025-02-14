#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <gtk/gtk.h>
#include <cairo.h>
#include <cstring>

class SmurfDetectionTool {
public:
    SmurfDetectionTool() : attack_count(0), normal_count(0) {}

    // Function to handle packets
    void detect_smurf_attack(const struct pcap_pkthdr *header, const u_char *packet, const std::string &target_ip) {
        struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header (14 bytes)

        if (ip_header->ip_p == IPPROTO_ICMP) {  // ICMP Protocol
            struct icmphdr *icmp_header = (struct icmphdr *)(packet + 14 + (ip_header->ip_hl << 2));

            // Check if the packet is an ICMP Echo Request
            if (icmp_header->type == ICMP_ECHO) {
                // Check if destination is a broadcast address
                if ((ip_header->ip_dst.s_addr & 0xFFFFFF00) == 0xFFFFFFFF) {  // Check if it's a broadcast address (ends with .255)
                    if (std::string(inet_ntoa(ip_header->ip_src)) == target_ip) {
                        attack_count++;
                    } else {
                        normal_count++;
                    }
                }
            }
        }
    }

    // Packet handler function
    static void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
        SmurfDetectionTool *tool = reinterpret_cast<SmurfDetectionTool *>(user_data);
        const std::string *target_ip = reinterpret_cast<std::string *>(user_data);
        tool->detect_smurf_attack(pkthdr, packet, *target_ip);
    }

    // Function to start sniffing for packets
    void start_sniffing(const std::string &dev, const std::string &target_ip) {
        pcap_t *handle;
        char errbuf[PCAP_ERRBUF_SIZE];

        // Open the device for packet capture
        handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            printf("Error opening device: %s\n", errbuf);
            return;
        }

        // Start sniffing packets
        pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char *>(this));
        pcap_close(handle);
    }

    // Function to create a pie chart with Cairo
    void draw_pie_chart(cairo_t *cr) {
        double attack_percentage = (double)attack_count / (attack_count + normal_count) * 100;
        double normal_percentage = 100.0 - attack_percentage;

        // Set up pie chart
        cairo_set_line_width(cr, 2);
        cairo_translate(cr, 200, 200); // Move to the center of the window

        // Draw Smurf Attack section (red)
        cairo_set_source_rgb(cr, 1.0, 0.0, 0.0); // Red color
        cairo_arc(cr, 0, 0, 100, 0, 2 * M_PI * (attack_percentage / 100));
        cairo_line_to(cr, 0, 0);
        cairo_fill(cr);

        // Draw Normal Traffic section (blue)
        cairo_set_source_rgb(cr, 0.0, 0.0, 1.0); // Blue color
        cairo_arc(cr, 0, 0, 100, 0, 2 * M_PI * (normal_percentage / 100));
        cairo_line_to(cr, 0, 0);
        cairo_fill(cr);
    }

    // GTK Window Setup
    static gboolean on_draw_event(GtkWidget *widget, cairo_t *cr, gpointer user_data) {
        SmurfDetectionTool *tool = reinterpret_cast<SmurfDetectionTool *>(user_data);
        tool->draw_pie_chart(cr);
        return FALSE;
    }

    // Main GTK window and callback setup
    void setup_gui() {
        GtkWidget *window;
        GtkWidget *entry;
        GtkWidget *button;
        GtkWidget *box;

        gtk_init(NULL, NULL);

        window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
        gtk_window_set_title(GTK_WINDOW(window), "Smurf Attack Detection Tool");
        gtk_window_set_default_size(GTK_WINDOW(window), 500, 400);
        g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

        box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
        gtk_container_add(GTK_CONTAINER(window), box);

        // Create Entry to input target IP
        entry = gtk_entry_new();
        gtk_box_pack_start(GTK_BOX(box), entry, TRUE, TRUE, 0);

        // Create button to start detection
        button = gtk_button_new_with_label("Detect Smurf Attack");
        g_signal_connect(button, "clicked", G_CALLBACK(on_button_click), this);
        gtk_box_pack_start(GTK_BOX(box), button, TRUE, TRUE, 0);

        // Create an area to draw the pie chart
        GtkWidget *drawing_area = gtk_drawing_area_new();
        gtk_box_pack_start(GTK_BOX(box), drawing_area, TRUE, TRUE, 0);
        g_signal_connect(drawing_area, "draw", G_CALLBACK(on_draw_event), this);

        gtk_widget_show_all(window);
        gtk_main();
    }

private:
    int attack_count;
    int normal_count;

    // Callback when button is clicked
    static void on_button_click(GtkWidget *widget, gpointer user_data) {
        SmurfDetectionTool *tool = reinterpret_cast<SmurfDetectionTool *>(user_data);
        const char *dev = pcap_lookupdev(NULL);
        if (dev == NULL) {
            printf("Device not found for sniffing.\n");
            return;
        }

        GtkWidget *entry = gtk_bin_get_child(GTK_BIN(widget));
        const char *target_ip = gtk_entry_get_text(GTK_ENTRY(entry));

        // Start sniffing in a separate thread
        tool->start_sniffing(dev, target_ip);
    }
};

int main(int argc, char *argv[]) {
    SmurfDetectionTool tool;
    tool.setup_gui();
    return 0;
}
