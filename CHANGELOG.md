# CHANGELOG



## v0.3.4 (2025-09-12)

###  

* fix broken refreshes after impersonation (#16)

* test for broken refreshes after impersonation

* fix with update to wipac_dev_tools

* fix non-optional arg

* fix extra arg

* back out new code to see if test fails

* add in new code to fix bug ([`1b44c5e`](https://github.com/WIPACrepo/scitoken-issuer/commit/1b44c5ea7470269297df93f5eb42f3635f15a3e7))

* [no-bump] update dockerfile build to better syntax (#15)

* update dockerfile build to better syntax

* fix cleanup of tmp files ([`887bc7b`](https://github.com/WIPACrepo/scitoken-issuer/commit/887bc7b55faea46b33c90a28fd76af3785937f45))


## v0.3.3 (2025-08-19)

###  

* add some more logging (#14) ([`63d47c2`](https://github.com/WIPACrepo/scitoken-issuer/commit/63d47c2d769b938cf7d2d960c0b4caa2d7a54bf8))


## v0.3.2 (2025-08-14)

###  

* update readme ([`7fcfec9`](https://github.com/WIPACrepo/scitoken-issuer/commit/7fcfec9fc360ace5ea50f795722a6fe0e4abe970))


## v0.3.1 (2025-08-14)

###  

* fix adding extra fields to return data (#13) ([`4a93bb1`](https://github.com/WIPACrepo/scitoken-issuer/commit/4a93bb1238b9927261699c08fa312383e02b6c56))


## v0.3.0 (2025-08-14)

### [minor]

* [minor] add client credentials and token exchange (#12)

* add client credentials and token exchange

* fix flake8 ([`9a96b64`](https://github.com/WIPACrepo/scitoken-issuer/commit/9a96b64b7058562597f04857a4ebb14cad307351))


## v0.2.0 (2025-07-24)

### [minor]

* [minor] Static clients (#10)

* script to delete old clients

* add static clients ([`6c8530a`](https://github.com/WIPACrepo/scitoken-issuer/commit/6c8530a26193c5ffd3e1bdeac937781d157b38f5))


## v0.1.2 (2025-07-21)

###  

* fix .well-known client registration url (#9) ([`cbf05c7`](https://github.com/WIPACrepo/scitoken-issuer/commit/cbf05c7bce9a1de5e82fab62c65fda71496485cb))


## v0.1.1 (2025-07-21)

###  

* fix CUSTOM_CLAIMS weird dataclass error (#8) ([`b5140d6`](https://github.com/WIPACrepo/scitoken-issuer/commit/b5140d66c9721dd97093c83ae4e933f67f5a97cf))


## v0.1.0 (2025-07-21)

### [minor]

* [minor] use custom claims overrides so we can directly specify special wlcg/scitoken claims (#7) ([`79a1623`](https://github.com/WIPACrepo/scitoken-issuer/commit/79a1623ec4767bc467454e5d0c59c50c2ca62646))


## v0.0.6 (2025-07-21)

###  

* make wlcg.ver a string (#6) ([`ec66d8f`](https://github.com/WIPACrepo/scitoken-issuer/commit/ec66d8f2df6722d3175a9c221f010b54fa806e47))


## v0.0.5 (2025-07-21)

###  

* adjust exp to use integer times (#5) ([`5adb974`](https://github.com/WIPACrepo/scitoken-issuer/commit/5adb974c7b69e15f3da7f6a9ae59afa3da30ee2b))


## v0.0.4 (2025-07-18)

###  

* some token adjustments for pelican (#4)

* make aud a list for pelican

* fix test ([`1731d67`](https://github.com/WIPACrepo/scitoken-issuer/commit/1731d6771b060f3b7c9933202893b76057fa8d3b))


## v0.0.3 (2025-07-18)

###  

* change mongo connection to fix issues (#3) ([`ec61f04`](https://github.com/WIPACrepo/scitoken-issuer/commit/ec61f049ccc0da87ffd40eab4f4c4e03d9e10241))


## v0.0.2 (2025-07-18)

###  

* fix container command (#2) ([`27247a5`](https://github.com/WIPACrepo/scitoken-issuer/commit/27247a5b25a1105b5b827afa51ba40d4ee00096e))


## v0.0.1 (2025-07-18)

###  

* first try at an issuer (#1)

* first try at an issuer

* fix linting issues

* fix mypy ([`b26e404`](https://github.com/WIPACrepo/scitoken-issuer/commit/b26e404dc17bcfb99c078bc4108da04bb03c22ea))

* Initial commit ([`7171f67`](https://github.com/WIPACrepo/scitoken-issuer/commit/7171f67c09787743ced536c06bfaf133552add03))
