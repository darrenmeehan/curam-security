{
  description = "curam security core — dev shell (Rust + Python + maturin + bwrap)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        packages = [
          pkgs.bubblewrap  # the cage (unprivileged, userns)
          pkgs.nftables   # nft (geo country sets in the cage)
          pkgs.python3     # pytest / maturin (3.12)
          pkgs.maturin     # abi3 wheel builder (pinned here)
          pkgs.rustc       # rust toolchain pinned by the flake lock
          pkgs.cargo
          pkgs.yq
        ];
        shellHook = ''
          echo "curam dev shell: $(bwrap --version) | $(cargo --version | head -1)"
        '';
      };
    };
}