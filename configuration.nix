{ config, pkgs, ...}: {
  imports = [
    ./hardware-configuration.nix
    <agenix/modules/age.nix>  # requires `nix-channel --add https://github.com/ryantm/agenix/archive/main.tar.gz agenix`
  ];

  nix.settings.auto-optimise-store = true;

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
  ];

  boot.tmp.cleanOnBoot = true;
  zramSwap.enable = true;

  networking.hostName = "mycloud-nixos";
  services.openssh.enable = true;
  users.users.root.openssh.authorizedKeys.keys = [
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDIzDCdxCAPnbdzwkKpp/9AUGMyABSPj/vZffRQoojdHh6Ct+9fZ60vYOS9NaQy9bqdagC0bHrrBvELiTqbAj5E3I1E7Mfp2BXjI/ig+NTlp0SIoaXnlLRNxnb+TSEDuAdqMdgwjxuy63T5PK04e7AH24NQ8J9sF16QAu0A0VurZEzPTLVZIoFCr/qmxZLnsJELdAtmnxCf+ZlBSs+v0qWOibOQ1mgKecii+0hRPSDpmY62FI++AzNoeVJ4j0ObSC/hpLMYkF5DJSkwaD+4+7CDLFhHdIQ5AzZNZp4gS2IESGUVTbUhXHm0YOr/xj66ZLqDzA16F+dSkKrnfRyTGrjdeWNsMTy42W42wEK1FhbHfsg4AQtT7S3kyiKS0lUFPdH34Q6iiTShTtySDCPW46hEp97sYshZ2aSDAIKYRty3mODPZlM12LL6z1bgbte6bsI3JN0nbIULemfgVqlZAHRDpCv05muEi4IPzYdDxMutAN8zNcMz3IyVoRQ/2bw2kds=" 
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEcP5JDW+JKSD04YGd+giu8oGCVGKjh7ZSap0UbNUYhP JuiceSSH"
  ];

  age.secrets = {
    nextcloud_admin_pass = {
      file = ./nextcloud_admin_pass.age;
      owner = "nextcloud";
    };
  };

  # Hosts something similar to a TOR proxy
  services.snowflake-proxy = {
    enable = true;
  };

  services.nextcloud = {
    enable = true;                   
    package = pkgs.nextcloud26;
    hostName = "storage.romeov.me";
    https = true;
    config.adminpassFile = config.age.secrets.nextcloud_admin_pass.path;
    home="/storage/nextcloud";
  };

  services.libreddit = {
    enable = true;
    address = "127.0.0.1";
    port = 8081;
  };
  systemd.services.libreddit.environment = {
    LIBREDDIT_DEFAULT_SHOW_NSFW = "on";
    LIBREDDIT_DEFAULT_USE_HLS = "on";
    LIBREDDIT_DEFAULT_HIDE_HLS_NOTIFICATION = "on";
    LIBREDDIT_DEFAULT_AUTOPLAY_VIDEOS = "on";
  };

  services.nitter = {
    enable = true;
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

  # The email setup doesn't work.
  # Currently, new users can be accepted via the mastodon cli.
  services.mastodon = {
    enable = true;
    localDomain = "social.romeov.me";
    configureNginx = true;
    smtp.fromAddress = "";
    mediaAutoRemove.olderThanDays = 7;
  };

  # If I don't have this my disk runs full quickly.
  systemd.timers."mastodon-clear-cache-timer" = {
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnBootSec = "3 days";
      OnUnitActiveSec = "3 days";
      Unit = "mastodon-clear-cache.service";
    };
  };
  systemd.services."mastodon-clear-cache" = {
    script = ''
      set -eu
      ${pkgs.coreutils}/bin/rm -r /var/lib/mastodon/public-system/cache || true  # don't fail if cache doesn't exist
    '';
    serviceConfig = {
      Type = "oneshot";
      User = "root";
    };
  };


  services.jitsi-meet = {
    enable = false;
    hostName = "meet.romeov.me";
    # caddy.enable = true;
  };
  
  services.headscale = {
    enable = false;
    port = 8083;
    # serverUrl = "https://headscale.romeov.me";
  };

  # we need these ports for nextcloud and libreddit
  # open http and https
  networking.firewall.allowedTCPPorts = [ 80 443 ];

  # Use nginx and ACME (Let's encrypt) to enable https
  services.nginx = {
    enable = true;
    recommendedProxySettings = true;
    recommendedTlsSettings = true;
    virtualHosts = {
      "storage.romeov.me" = {
        ## Force HTTP redirect to HTTPS
        forceSSL = true;
        ## LetsEncrypt
        enableACME = true;
      };
      "libreddit.romeov.me" = {
        ## Force HTTP redirect to HTTPS
        forceSSL = true;
        ## LetsEncrypt
        enableACME = true;
        locations."/" = {
          proxyPass = "http://127.0.0.1:8081";
        };
      };
      "nitter.romeov.me" = {
        ## Force HTTP redirect to HTTPS
        forceSSL = true;
        ## LetsEncrypt
        enableACME = true;
        locations."/" = {
          proxyPass = "http://127.0.0.1:8082";
        };
      };
      "headscale.romeov.me" = {
         ## Force HTTP redirect to HTTPS
         forceSSL = true;
         ## LetsEncrypt
         enableACME = true;
         locations."/" = {
           proxyPass = "http://127.0.0.1:8083";
         };
      };
    };
  };
  security.acme = {
    acceptTerms = true;
    defaults.email = "contact@romeov.me";
  };

  ## system specific section
  ## probably I could/should move this to another file?
  # mount hetzner volume
  fileSystems."/storage" =
    { device = "/dev/disk/by-id/scsi-0HC_Volume_23527885";
      fsType = "ext4";
    };

  # set up ipv6
  networking = {
    interfaces.enp1s0.ipv6.addresses = [{
      address = "2a01:4ff:f0:e2df::";
      prefixLength = 64;
    }];
    defaultGateway6 = {
      address = "fe80::1";
      interface = "enp1s0";
    };
  };
}
