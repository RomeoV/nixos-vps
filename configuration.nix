{ config, lib, pkgs, ... }: 
let
  unstable = import <nixos-unstable> {};
  pkgs_unstable = unstable.pkgs;
in {
  imports =   [
    ./hardware-configuration.nix
    ./networking.nix # generated at runtime by nixos-infect
    <agenix/modules/age.nix>  # requires `nix-channel --add https://github.com/ryantm/agenix/archive/main.tar.gz agenix`
    (import /etc/nixos/redlib_service.nix {inherit lib config pkgs_unstable; })
  ];

  system.stateVersion = "22.05";

  nix.settings.experimental-features = "nix-command flakes";
  # nix.allowedUsers = [ "@wheel" ];
  nix.settings.allowed-users = [ "root" ];

  nixpkgs.config.allowUnfree = true;

  time.timeZone = "America/Los_Angeles";

  system.autoUpgrade = {
    enable = true;
    allowReboot = true;
    randomizedDelaySec = "10min";
    dates = "Mon,Fri 04:40";
  };
  nix.gc = {
    automatic = true;
    dates = "weekly";
    options = "--delete-older-than 90d";
  };
  services.journald.extraConfig = "SystemMaxUse=1000M";

  boot.tmp.cleanOnBoot = true;
  zramSwap.enable = true;
  networking.hostName = "mycloud-nixos";
  networking.domain = "romeov.me";
  services.openssh.enable = true;
  users.users.root.openssh.authorizedKeys.keys = [
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDIzDCdxCAPnbdzwkKpp/9AUGMyABSPj/vZffRQoojdHh6Ct+9fZ60vYOS9NaQy9bqdagC0bHrrBvELiTqbAj5E3I1E7Mfp2BXjI/ig+NTlp0SIoaXnlLRNxnb+TSEDuAdqMdgwjxuy63T5PK04e7AH24NQ8J9sF16QAu0A0VurZEzPTLVZIoFCr/qmxZLnsJELdAtmnxCf+ZlBSs+v0qWOibOQ1mgKecii+0hRPSDpmY62FI++AzNoeVJ4j0ObSC/hpLMYkF5DJSkwaD+4+7CDLFhHdIQ5AzZNZp4gS2IESGUVTbUhXHm0YOr/xj66ZLqDzA16F+dSkKrnfRyTGrjdeWNsMTy42W42wEK1FhbHfsg4AQtT7S3kyiKS0lUFPdH34Q6iiTShTtySDCPW46hEp97sYshZ2aSDAIKYRty3mODPZlM12LL6z1bgbte6bsI3JN0nbIULemfgVqlZAHRDpCv05muEi4IPzYdDxMutAN8zNcMz3IyVoRQ/2bw2kds=" 
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEcP5JDW+JKSD04YGd+giu8oGCVGKjh7ZSap0UbNUYhP JuiceSSH"
  ];

  # see https://xeiaso.net/blog/paranoid-nixos-2021-07-18/, "Audit tracing"
  security.auditd.enable = true;
  security.audit.enable = true;
  security.audit.rules = [
    "-a exit,always -F arch=b64 -S execve"
  ];

  programs = {
    mosh.enable = true;
    git.enable = true;
    neovim = {
      enable = true;
      defaultEditor = true;
      withPython3 = false;
      withRuby = false;
    };
  };

  environment.systemPackages = [
      (pkgs.callPackage <agenix/pkgs/agenix.nix> {})
      pkgs.helix
      pkgs.headscale
      pkgs.rclone
      pkgs.bottom
      # pkgs.onlyoffice-documentserver
      # pkgs.docker-compose  
      pkgs.podman-compose  
      unstable.pkgs.redlib
  ];

  ## get ready for docker compose
  # from https://discourse.nixos.org/t/docker-compose-on-nixos/17502/2
  # Pick one
  # virtualisation.docker.enable = true;
  virtualisation = {
    podman = {
      enable = true;

      # Create a `docker` alias for podman, to use it as a drop-in replacement
      dockerCompat = true;

      # Required for containers under podman-compose to be able to talk to each other.
      defaultNetwork.settings.dns_enabled = true;
    };
  };
  # virtualisation.podman.enable = true;
  # users.users.root.extraGroups = [ "docker" ];
  # users.users.postgres-immich = {
  #   isNormalUser = false;
  #   description = "postgres user for Immich App.";
  #   # extraGroups = [ postgres ];
  # };

  # services.libreddit = {
  #   enable = true;
  #   address = "127.0.0.1";
  #   port = 8081;
  # };
  # systemd.services.libreddit.environment = {
  #   LIBREDDIT_DEFAULT_SHOW_NSFW = "on";
  #   LIBREDDIT_DEFAULT_USE_HLS = "on";
  #   LIBREDDIT_DEFAULT_HIDE_HLS_NOTIFICATION = "on";
  #   LIBREDDIT_DEFAULT_AUTOPLAY_VIDEOS = "on";
  # };
  services.redlib = {
    enable = true;
    address = "127.0.0.1";
    port = 8081;
  };
  systemd.services.redlib.environment = {
    REDLIB_DEFAULT_SHOW_NSFW = "on";
    REDLIB_DEFAULT_USE_HLS = "on";
    REDLIB_DEFAULT_HIDE_HLS_NOTIFICATION = "on";
    REDLIB_DEFAULT_AUTOPLAY_VIDEOS = "on";
  };

  services.nitter = {
    enable = false;
    server = {
      port = 8082;
      https = true;
      hostname = "nitter.romeov.me";
    };
    preferences = {
      replaceTwitter = "nitter.romeov.me";
      hlsPlayback = true;
      muteVideos = true;
      hideTweetStats = true;
    };
  };

  services.gotosocial = {
    enable = true;
    # setupPostgresqlDB = true;
    settings.host = "gts.romeov.me";
    settings.port = 8089;
    # storage-local-base-path = "/storage/gotosocial";
  };


  services.headscale = {
    enable = true;
    port = 8083;
    settings = {
      serverUrl = "https://headscale.romeov.me";
      # dns_config = { baseDomain = "romeov.me"; };
      # logtail.enabled = false; 
    };
  };

  services.tailscale = {
    enable = true;
  };

  age.secrets = {
    nextcloud_admin_pass = {
      file = ./nextcloud_admin_pass.age;
      owner = "nextcloud";
    };
    hetzner_private_key = {
      file = ./hetzner_private_key.age;
      owner = "root";
    };
    backblaze_env.file = ./backblaze_env.age;
    backblaze_repo.file = ./backblaze_repo.age;
    backblaze_password.file = ./backblaze_password.age;
  };
  services.nextcloud = {
    enable = true;                   
    package = pkgs.nextcloud28;
    hostName = "storage.romeov.me";
    https = true;
    config.adminpassFile = config.age.secrets.nextcloud_admin_pass.path;
    # config.adminpassFile = "/etc/nixos/nextcloud_pass";
    home="/storage/nextcloud";
  };
  services.onlyoffice = {
    enable = false;
    hostname = "localhost";
  };

  services.invidious = {
    enable = true;
    port = 8090;
    settings.db.user = "invidious";
  };

  services.syncthing = {
    enable = false;
    # user = "nextcloud";  # so that we can write to the WebDAV folders.
    # group = "nextcloud";  # so that we can write to the WebDAV folders.
  };


  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ 
      80 
      443    
      # config.services.grafana.settings.server.http_port 
    ];
    trustedInterfaces = [
      "tailscale0"
    ];
  };
  # Use nginx and ACME (Let's encrypt) to enable https
  services.nginx = {
    enable = true;
    recommendedProxySettings = true;
    recommendedTlsSettings = true;
    clientMaxBodySize = "40M";
    virtualHosts = {
      # "localhost".listen = [ { addr = "127.0.0.1"; port = 8084; } ];
      "storage.romeov.me" = {
        ## Force HTTP redirect to HTTPS
        forceSSL = true;
        ## LetsEncrypt
        useACMEHost = "romeov.me";
      };
      "libreddit.romeov.me" = {
        ## Force HTTP redirect to HTTPS
        forceSSL = true;
        ## LetsEncrypt
        useACMEHost = "romeov.me";
        locations."/" = {
          proxyPass = "http://127.0.0.1:8081";
        };
      };
      "nitter.romeov.me" = {
        ## Force HTTP redirect to HTTPS
        forceSSL = true;
        ## LetsEncrypt
        useACMEHost = "romeov.me";
        locations."/" = {
          proxyPass = "http://127.0.0.1:8082";
        };
      };
      "headscale.romeov.me" = {
         ## Force HTTP redirect to HTTPS
         forceSSL = true;
         ## LetsEncrypt
         useACMEHost = "romeov.me";
         locations."/" = {
         proxyPass = "http://127.0.0.1:8083";
         proxyWebsockets = true;
        };
      };
      "immich.romeov.me" = {
         ## Force HTTP redirect to HTTPS
         forceSSL = true;
         ## LetsEncrypt
         useACMEHost = "romeov.me";
         locations."/" = {
         proxyPass = "http://127.0.0.1:2283";
        };
      };
      "gts.romeov.me" = with config.services.gotosocial.settings; {
        useACMEHost = "romeov.me";
        forceSSL = true;
        locations = {
          "/" = {
            recommendedProxySettings = true;
            proxyWebsockets = true;
            proxyPass = "http://${bind-address}:${toString port}";
          };
        };
      };
      # "grafana.romeov.me" = {
      #   locations."/" = {
      #       proxyPass = "http://127.0.0.1:${toString config.services.grafana.settings.server.http_port}";
      #       proxyWebsockets = true;
      #       recommendedProxySettings = true;
      #   };
      # };
      # "romeov.me" =  with config.services.gotosocial.settings; {
      "romeov.me" = {
        enableACME = true;
        forceSSL = true;
        locations = {
          "/" = {
            extraConfig = ''
                rewrite ^.*$ https://page.romeov.me permanent;
            '';
          };
          # "/.well-known/webfinger" = {
          #   extraConfig = ''
          #       rewrite ^.*$ https://gts.romeov.me/.well-known/webfinger permanent;
          #   '';
          # };
          # "/.well-known/host-meta" = {
          #   extraConfig = ''
          #     rewrite ^.*$ https://gts.romeov.me/.well-known/host-meta permanent;
          #   '';
          # };
          # "/.well-known/nodeinfo" = {
          #   extraConfig = ''
          #     rewrite ^.*$ https://gts.romeov.me/.well-known/nodeinfo permanent;
          #   '';
          # };

          # "/" = {
          #   recommendedProxySettings = true;
          #   proxyWebsockets = true;
          # };
          # "/well-known" = {
          #   recommendedProxySettings = true;
          #   proxyWebsockets = true;
          #   # globalRedirect = "gts.romeov.me";
          # };
        };
      };
    };
  };
  security.acme = {
    acceptTerms = true;
    defaults.email = "contact@romeov.me";
    certs."romeov.me".extraDomainNames = [
     "gts.romeov.me"
     "headscale.romeov.me"
     "libreddit.romeov.me"
     "storage.romeov.me"
     "nitter.romeov.me"
     "immich.romeov.me"
    ];
  };


  # Set up some logging
  services.grafana = {
    enable = true;
    # settings.server.domain = "grafana.romeov.me";
    settings.server.http_port = 3000;
    # settings.server.http_addr = "127.0.0.1;0.0.0.0";
    settings.server.http_addr = "0.0.0.0";
  };
  services.prometheus = {
    enable = true;
    port = 9001;
    exporters = {
      node = {
        enable = true;
        enabledCollectors = [ "systemd" ];
        port = 9002;
      };
    };
    scrapeConfigs = [
      {
        job_name = "prometheus-collect-data";
        static_configs = [{
          targets = [ "127.0.0.1:${toString config.services.prometheus.exporters.node.port}" ];
        }];
      }
    ];
  };

  services.restic.backups = {
    daily = {
      initialize = true;

      environmentFile = config.age.secrets."backblaze_env".path;
      repositoryFile = config.age.secrets."backblaze_repo".path;
      passwordFile = config.age.secrets."backblaze_password".path;

      paths = [
        "/etc/nixos"
        "/storage/immich"
        "/storage/nextcloud"
      ];

      pruneOpts = [
        "--keep-daily 7"
        "--keep-weekly 5"
        "--keep-monthly 12"
      ];
    };
  };


  ## system specific section
  ## probably I could/should move this to another file?
  # mount hetzner volume
#   fileSystems."/storage" =
#     { device = "/dev/disk/by-id/scsi-0HC_Volume_23527885";
#       fsType = "ext4";
#       neededForBoot = false;
#     };
  # systemd.mounts = [{
  #     description = "Storage Box (via rclone)";
  #     after = [ "network-online.target" ];
  #     what = "storage-box:";
  #     where = "/mnt/storage-box";
  #     type = "rclone";
  #     options = "rw,_netdev,allow_other,args2env,vfs-cache-mode=writes,log-level=DEBUG,config=/root/.config/rclone/rclone.conf,cache-dir=/var/rclone-cache";
  #   }]; 
    fileSystems."/mnt/storage-box" = {
      device = "storage-box:";
      fsType = "rclone";
      neededForBoot = false;
      options = [
        "ro"
        "allow_other"
        "_netdev"
        "noauto"
        "x-systemd.automount"
        "x-systemd.idle-timeout=60"
    
        # rclone specific
        "env.PATH=/run/wrappers/bin" # for fusermount3
        "config=/root/.config/rclone/rclone.conf"
        "cache_dir=/storage/cache/rclone-mount"
        "vfs-cache-mode=full"
      ];
    };

}
