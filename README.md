# pyCountryBlock
Script to pull country block lists, combine them, and write them to nftables.

To be clear, the "list of rules" this guy creates is not optimal. This should really update an nftables set, then test based on the set.

But really, country blocking isn't optimal anyways. I don't use this script on my servers.

USAGE
-t : Test. This runs through a series of tests for the CIDR Range combiner stuff.
--pretend: Pretend. This prevents any changes from actually being written to the FW.
