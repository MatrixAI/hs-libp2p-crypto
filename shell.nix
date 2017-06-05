{nixpkgs ? import <nixpkgs> {}, ghc ? nixpkgs.ghc}:

with nixpkgs;

haskell.lib.buildStackProject {
  name = "hs-libp2p-crypto";
  buildInputs = [ stack cabal-install ];
  inherit ghc;
}
