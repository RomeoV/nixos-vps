{ config, pkgs, ...}: {
  imports = [
    ./hardware-configuration.nix
  ];

  environment.systemPackages = [
    pkgs.vim
    pkgs.git
  ];

  boot.cleanTmpDir = true;
  zramSwap.enable = true;

  networking.hostName = "mycloud-nixos";
  services.openssh.enable = true;
  users.users.root.openssh.authorizedKeys.keys = [
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDIzDCdxCAPnbdzwkKpp/9AUGMyABSPj/vZffRQoojdHh6Ct+9fZ60vYOS9NaQy9bqdagC0bHrrBvELiTqbAj5E3I1E7Mfp2BXjI/ig+NTlp0SIoaXnlLRNxnb+TSEDuAdqMdgwjxuy63T5PK04e7AH24NQ8J9sF16QAu0A0VurZEzPTLVZIoFCr/qmxZLnsJELdAtmnxCf+ZlBSs+v0qWOibOQ1mgKecii+0hRPSDpmY62FI++AzNoeVJ4j0ObSC/hpLMYkF5DJSkwaD+4+7CDLFhHdIQ5AzZNZp4gS2IESGUVTbUhXHm0YOr/xj66ZLqDzA16F+dSkKrnfRyTGrjdeWNsMTy42W42wEK1FhbHfsg4AQtT7S3kyiKS0lUFPdH34Q6iiTShTtySDCPW46hEp97sYshZ2aSDAIKYRty3mODPZlM12LL6z1bgbte6bsI3JN0nbIULemfgVqlZAHRDpCv05muEi4IPzYdDxMutAN8zNcMz3IyVoRQ/2bw2kds=" 
  ];

  services.nextcloud = {                
    enable = true;                   
    package = pkgs.nextcloud24;
    hostName = "storage.romeov.me";
    https = true;
    config.adminpassFile = "/home/nextcloud_admin_pass";
    home="/storage";
  };
  # we need these ports for nextcloud
  networking.firewall.allowedTCPPorts = [ 80 443 ];

  # Use nginx and ACME (Let's encrypt) to enable https
  services.nginx = {
    enable = true;
    virtualHosts = {
      "storage.romeov.me" = {
        ## Force HTTP redirect to HTTPS
        forceSSL = true;
        ## LetsEncrypt
        enableACME = true;
      };
    };
  };
  security.acme = {
    acceptTerms = true;
    defaults.email = "contact@romeov.me";
  };

  # mount hetzner volume
  fileSystems."/storage" =
    { device = "/dev/disk/by-id/scsi-0HC_Volume_23527885";
      fsType = "ext4";
    };
}
