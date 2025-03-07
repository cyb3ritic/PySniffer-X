class Settings:
    # Logging
    LOG_LEVEL = "INFO"
    
    # Capture
    DEFAULT_INTERFACE = "eth0"
    DEFAULT_FILTER = "tcp or udp"
    
    # Output
    PCAP_AUTO_SAVE = True
    MAX_PACKETS = 1000  # 0 = unlimited