FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap hydra hping3 curl dnsutils ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && printf 'admin\n123456\npassword\nletmein\nqwerty\nroot\ntoor\nwelcome\n' > /wordlist.txt
COPY attack.sh /usr/local/bin/attack
RUN chmod +x /usr/local/bin/attack
ENTRYPOINT ["sleep", "infinity"]
