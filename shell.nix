{nixpkgs ? import <nixpkgs> {}, ghc ? nixpkgs.ghc}:

with nixpkgs;

haskell.lib.buildStackProject {
  name = "libp2p-crypto";
  buildInputs = [ stack cabal-install autoreconfHook ];
  inherit ghc;
}
