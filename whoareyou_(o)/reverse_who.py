
ror = lambda val, r_bits, max_bits=64: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

rol = lambda val, r_bits, max_bits=64: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

rbx = 0x6BA8F103D6E0FF17
rax = 0x7621C6C017B39653
rbx ^= rax
rax = 0xC5DAAB36B8BB75B5
rbx -= rax

rbx = ror(rbx,0x29)
rbx = ror(rbx,0x4B)
rbx = rol(rbx,-0x2F&0xff)
rax = 0x898069F543450EB7
rbx ^= rax

rbx = ror(rbx,-0x1A&0xff)
rax = 0xE36982FB4814BBEB
rbx -= rax
rax = 0xB6255E92D0FDD3C3
rbx -= rax
rax = 0xBC2EE8A7EF7D36FC
rbx ^= rax
rax = 0xAD25C722CAD8EB0F
rbx ^= rax
rax = 0x9F7928B9D52B900C
rbx -= rax
rax = 0xA5E18548FB495F0E
rbx ^= rax
rax = 0x59196F6D2E5520AE
rbx -= rax
rax = 0x68FE69A4CAA792AA
rbx -= rax
rax = 0x447E36FFD20548EA
rbx -= rax
rax = 0xD0641F227EB4D6B4
rbx -= rax
rax = 0x61A82F9CF681337C
rbx ^= rax
rax = 0x8AF8FB35F294F6C1
rbx ^= rax
rax = 0x49B2746007510470
rbx ^= rax
rax = 0x2BE97387B605902B
rbx += rax

rbx = rol(rbx,0x15)
rbx = rol(rbx,0x52)
rax = 0xE993678FBDBA82BA
rbx ^= rax

rbx = rol(rbx,0x0A)
rbx = rol(rbx,-0x18&0xff)
rax = 0xB8BAC2D9D73CCBE4
rbx += rax
rax = 0x54EDCFD23DAF8D18
rbx += rax
rax = 0x909FF96F38559937
rbx ^= rax
rax = 0x54948C6944BD3B1B
rbx += rax
rax = 0x8696642DC14B5618
rbx += rax
rax = 0x4FCBFCA2960B5A52
rbx -= rax
rax = 0x2EFBDD2C3D1D154E
rbx ^= rax
rax = 0x1D028A6B035A0F7C
rbx += rax
rax = 0x5B28A10F15E8091E
rbx += rax

rbx = ror(rbx,0x2A)
rax = 0xDAAF58A2709877BA
rbx += rax

rbx = rol(rbx,-0x4D&0xff)
rbx = ror(rbx,-0x54&0xff)
rax = 0x745C9347B6FE7ED9
rbx ^= rax
rax = 0x81F93162321F12C5
rbx += rax

rbx = rol(rbx,-0x39&0xff)
rax = 0xB7399F55F36E6188
rbx ^= rax
rax = 0x4109C7937C0763F7
rbx -= rax

rbx = ror(rbx,0x3F)
rbx = ror(rbx,0x53)
rax = 0xE8A98BB5E44D7898
rbx -= rax

rbx = rol(rbx,0x18)
rbx = ror(rbx,0x10)
rbx = ror(rbx,0x5F)
rbx = ror(rbx,-0x10&0xff)
rax = 0x84B0516122E071F2
rbx -= rax
rax = 0x4A19E74D36F9747C
rbx += rax
rax = 0x9AF87325227991B9
rbx ^= rax

rbx = ror(rbx,-0x38&0xff)
rbx = rol(rbx,0x15)
rbx = ror(rbx,0x71)
rbx = ror(rbx,-0x63&0xff)
rax = 0xD0F21FEA955FCE2A
rbx += rax

rbx = ror(rbx,-0x3A&0xff)
rax = 0x724B7BA98EFE47D5
rbx += rax
rax = 0x11360CDA24AB680B
rbx += rax
rax = 0xF9149F0F623FF23C
rbx += rax
rax = 0xB65D5E7379F160F7
rbx ^= rax
rax = 0x7A365A57ACF2DA7B
rbx ^= rax

rbx = ror(rbx,-0x5E&0xff)
rbx = rol(rbx,0x23)
rbx = rol(rbx,0x08)
rbx = ror(rbx,-0x58&0xff)
rbx = ror(rbx,-0x4A&0xff)
rax = 0x42F06CE7AE8ECD1A
rbx += rax

rbx = rol(rbx,0x7E)
rax = 0x54E570FC26DB4404
rbx -= rax
rax = 0x93D7F3341E15748D
rbx += rax

rbx = rol(rbx,0x2C)
rax = 0x2B1FAEF6F77F9547
rbx += rax

rbx = rol(rbx,-0x15&0xff)
rbx = ror(rbx,0x1)
rax = 0x8FCE34693DB900FA
rbx -= rax

rbx = ror(rbx,-0x67&0xff)
rax = 0x14937F64BB66B2B7
rbx ^= rax
rax = 0x84E73F3A58B88403
rbx += rax
rax = 0xBECAFFA0E7364387
rbx += rax

rbx = ror(rbx,-0x28&0xff)
rax = 0xFC8EF9C0546CF1DA
rbx -= rax

rbx = rol(rbx,0x4F)
rax = 0x75F1387D11723D15
rbx -= rax
rax = 0xA8DC1CF09F6DE089
rbx -= rax

rbx = ror(rbx,-0x08&0xff)
rax = 0xB0322C6183BCB663
rbx += rax
rax = 0x66694D2034F98052
rbx -= rax
rax = 0x060D38673CCB4E61
rbx += rax
rax = 0xCA8F3A9B44805D42
rbx -= rax
rax = 0x5EFB672197377396
rbx ^= rax

rbx = ror(rbx,-0x70&0xff)
rbx = rol(rbx,0x61)
rax = 0x17EABE1E2ED93BED
rbx += rax
rax = 0x2297CA274AD16880
rbx += rax

rbx = ror(rbx,0x50)
rax = 0xECD81BF26399FCFD
rbx += rax
rax = 0x65C31CCB80F461CD
rbx -= rax
rax = 0x92D72D4942CFDA0E
rbx ^= rax
rax = 0x546271E81E8C27E1
rbx -= rax
rax = 0x6F2C12732F7C9292
rbx ^= rax

rbx = ror(rbx,0x6B)
rax = 0xC2571DB7FF2545F9
rbx += rax
rax = 0x1A8A0E309BDF22B4
rbx ^= rax
rax = 0x1E64F880B4AC0124
rbx -= rax
rax = 0xEECF38FBEA9C2C1A
rbx -= rax
rax = 0x2BEE486488C30F94
rbx += rax
rax = 0x5C45130F3A5E483E
rbx += rax

rbx = ror(rbx,0x4B)
rax = 0xFA25B758575D5C77
rbx -= rax
rax = 0x1C13424C6547378C
rbx ^= rax
rax = 0x5D63E2F593B40CBB
rbx ^= rax
rax = 0x0EFA49B5658D382E
rbx += rax
rax = 0x001B45C647FF5E03
rbx -= rax
rax = 0x68AA064240576C44
rbx += rax
rax = 0xDF255A19B07FFF58
rbx ^= rax
rax = 0xB6CE7A7B423D3047
rbx += rax
rax = 0x51E028C0701601B3
rbx ^= rax

rbx = ror(rbx,-0x73&0xff)
rax = 0xDF123396B5A838A4
rbx -= rax
rax = 0xF682F04746346AFE
rbx -= rax
rax = 0x664D10179AA1C1F3
rbx -= rax
rax = 0xD96183EE64611689
rbx += rax
rax = 0x23BEDBD90CCC00A3
rbx -= rax

rbx = rol(rbx,0x4F)
rax = 0x14B7B0415B2F5978
rbx -= rax

rbx = rol(rbx,0x7F)
rbx = ror(rbx,-0x7F&0xff)
rax = 0x401068CBBB34D280
rbx += rax
rax = 0x91C5DDF3BFC466A9
rbx ^= rax
rax = 0x33AE8EA3C6218F66
rbx += rax
rax = 0x8E22FE1E1428CDA1
rbx += rax

rbx = rol(rbx,-0x40&0xff)
rbx = ror(rbx,0x79)
rax = 0x362CD57F45CF7617
rbx -= rax
rax = 0xD5AFA97D1CC26137
rbx += rax
rax = 0x8D35E8D77ACC2F8D
rbx += rax
rax = 0x240EE9CEE987F4DC
rbx -= rax

rbx = ror(rbx,-0x61&0xff)
rbx = ror(rbx,0x51)
rbx = ror(rbx,-0x33&0xff)
rax = 0x1152B445C317F9FD
rbx ^= rax

rbx = ror(rbx,0x5E)
rax = 0x069AD565703874AF
rbx += rax
rax = 0xB03F28C81A34D904
rbx -= rax
rax = 0xA2665A241EAF6968
rbx ^= rax

rbx = rol(rbx,-0x51&0xff)
rax = 0x0780C0BD80E3B046
rbx -= rax

rbx = ror(rbx,-0x3E&0xff)
rax = 0xECB48E3D5D62F179
rbx += rax

rbx = ror(rbx,-0x71&0xff)
rax = 0x22BF714C4504557A
rbx ^= rax
rax = 0xC3A3803360F73167
rbx += rax
rax = 0x265304C5209B6AC3
rbx ^= rax
rax = 0x26E3C1049BF915D9
rbx += rax
rax = 0x97001B777E826E4F
rbx ^= rax

rbx = rol(rbx,0x46)
rax = 0x1178E288F0DA177F
rbx += rax
rax = 0x079A426EE9A2439F
rbx -= rax

rbx = rol(rbx,-0x7A&0xff)
rax = 0xCB8376EEAAFBBEA3
rbx += rax
rax = 0xB29AB9D7FF04AECF
rbx -= rax

rbx = ror(rbx,-0x21&0xff)
rax = 0xAE98685038125F76
rbx += rax
rax = 0x28D9ACB57167B1BA
rbx ^= rax

rbx = ror(rbx,-0x7F&0xff)
rbx = rol(rbx,-0x56&0xff)
rbx = rol(rbx,-0x37&0xff)
rax = 0x3E51B6C23AFE841E
rbx -= rax
rax = 0x74348F4EA13526DE
rbx -= rax

rbx = ror(rbx,-0x58&0xff)
rax = 0xB74B23C80F825657
rbx -= rax
rax = 0x58DCFED81C0BC75A
rbx += rax
rax = 0x2E73D1364DEEFAFC
rbx ^= rax

rbx = rol(rbx,0x6F)
rax = 0xA1DA5E891D897A1E
rbx ^= rax

rbx = rol(rbx,0x23)
rax = 0xEAD4316212C28EA4
rbx += rax
rax = 0x45FEBADB38E5B9DE
rbx -= rax

rbx = rol(rbx,-0x1D&0xff)
rax = 0x785A7A1C0A25DD91
rbx -= rax

rbx = ror(rbx,-0x15&0xff)
rax = 0x8D1DB2E0697CE561
rbx ^= rax
rax = 0xCBEE6FC98B111D4D
rbx += rax
rax = 0x0A4860E6D1E87F5B
rbx ^= rax
rax = 0x30D0079B89940DC2
rbx ^= rax

rbx = rol(rbx,0x53)
rax = 0x32045E5A441365A1
rbx += rax
rax = 0x625A22783605F95A
rbx -= rax
rax = 0xF030A53B093ED287
rbx -= rax
rax = 0xCE83DA31B329177C
rbx ^= rax
rax = 0xEE8A92288F604111
rbx += rax

rbx = rol(rbx,-0x23&0xff)
rax = 0x8D6B664E37316D9E
rbx -= rax

rbx = ror(rbx,-0x28&0xff)
rax = 0xDF96C17E497BAFED
rbx ^= rax
rax = 0xF422A9DAA495019C
rbx ^= rax

rbx = ror(rbx,-0x19&0xff)
rax = 0x976A4F5A1D99C29B
rbx ^= rax
rax = 0x0A3F05649FEA2C10
rbx += rax
rax = 0xD20666F9FE219D88
rbx += rax

rbx = rol(rbx,-0x77&0xff)
rax = 0xFABE95EC2A9E154D
rbx -= rax
rax = 0xEA13B372E7BA706A
rbx -= rax

rbx = ror(rbx,0x1F)
rbx = rol(rbx,0x34)
rax = 0x0E8C8A1BDE83B982
rbx += rax

rbx = rol(rbx,-0x6E&0xff)
rbx = rol(rbx,0x04)
rax = 0x1792BA3C600A6EDF
rbx += rax
rax = 0x38530142F9D8A760
rbx ^= rax

rbx = rol(rbx,0x5E)
rax = 0x6FC09F1A7670E641
rbx += rax
rax = 0x5B48728221561403
rbx += rax

rbx = rol(rbx,0xff&-0x51)
rbx = ror(rbx,0xff&-0x22)
rax = 0x7B069868CCE7BB33
rbx -= rax

rbx = ror(rbx,0xff&-0x70)
rax = 0x4052D6D5C5F7C0ED
rbx -= rax

rbx = rol(rbx,0x77)
rax = 0xF827467D3D5A5374
rbx -= rax

rbx = ror(rbx,0xff&-0x25)
rax = 0x51B7F304D06D13F5
rbx += rax

rbx = rol(rbx,0xff&-0x33)
rbx = ror(rbx,0xff&-0x03)
rax = 0x732605939AE45657
rbx += rax

rbx = rol(rbx,0xff&-0x31)
rbx = rol(rbx,0x7C)
rax = 0xF6C8BC362C73490E
rbx ^= rax
rax = 0xDE5323385D248DBD
rbx ^= rax
rax = 0x80399332C6AC40C6
rbx ^= rax

rbx = ror(rbx,0xff&-0x2F)
rbx = rol(rbx,0x4F)
rax = 0xF7F6537CEBA2ADCB
rbx ^= rax

rbx = ror(rbx,0xff&-0x6B)
rax = 0xBBE09D7C1FCC2513
rbx += rax

rbx = ror(rbx,0xff&-0x07)
rbx = ror(rbx,0x69)
rax = 0x1277D7F87BC64FD0
rbx ^= rax

rbx = ror(rbx,0x21)
rax = 0xCF710B4480FCBF92
rbx -= rax

rbx = ror(rbx,0xff&-0x1A)
rbx = ror(rbx,0x49)
rax = 0xA5AA6926F40B1D7E
rbx ^= rax
rax = 0xDDD79B67B35B741B
rbx += rax

rbx = rol(rbx,0x0C)
rax = 0x8CC636EB93AE1F50
rbx -= rax

rbx = ror(rbx,0x16)
rax = 0x840DCC4A39C7A406
rbx -= rax
rax = 0x8DEF0B19794BF225
rbx += rax
rax = 0xFCDB6D1BE2ED1C6C
rbx -= rax

rbx = rol(rbx,0xff&-0x7A)
rax = 0xC2AA044A171BB533
rbx -= rax
rax = 0x469AB09173F0C14E
rbx ^= rax

rbx = rol(rbx,0x53)
rax = 0x52E2D48EEE12A660
rbx -= rax

rbx = rol(rbx,0xff&-0x3C)
rax = 0x8A3AE20FD8C82EF5
rbx -= rax
rax = 0x58571A9D91176A03
rbx ^= rax
rax = 0x20CDA706AF1D417D
rbx ^= rax

rbx = rol(rbx,0xff&-0x4B)
rax = 0xC66A8ABF880D879D
rbx -= rax

rbx = ror(rbx,0x2D)
rax = 0x129091EFF312D03A
rbx += rax
rax = 0x78AA6420C1CCA0F9
rbx += rax
rax = 0xB0B1FFEAB2AA510A
rbx -= rax

rbx = rol(rbx,0x39)
rbx = ror(rbx,0x1D)
rbx = ror(rbx,0xff&-0x70)
rax = 0x148BF841DDCA0A04
rbx -= rax

rbx = rol(rbx,0xff&-0x55)
rax = 0xFCE787DDD21CE57C
rbx -= rax
rax = 0xA96650C5EDB3D4E2
rbx ^= rax
rax = 0x98EA0AB50E35C537
rbx ^= rax

rbx = ror(rbx,0x6E)
rax = 0xEEA1D3D6ABF113D9
rbx ^= rax

rbx = rol(rbx,0x29)
rax = 0xC4C515B6912ECF74
rbx += rax

rbx = ror(rbx,0x43)
rbx = rol(rbx,0x72)
rax = 0xDB1E9A81BD59CBB7
rbx ^= rax
rax = 0x356E558DF007FE4A
rbx -= rax

rbx = rol(rbx,0xff&-0x6A)
rbx = ror(rbx,0xff&-0x3D)
rax = 0xB9296608ED164841
rbx -= rax
rax = 0xFC6AA5FC7408B3A8
rbx -= rax

rbx = rol(rbx,0xff&-0x3F)
rbx = rol(rbx,0xff&-0x39)
rax = 0xAD7B95EE0DB1078F
rbx -= rax
rax = 0x5C41DF37E7E21058
rbx ^= rax

rbx = ror(rbx,0xff&-0x29)
rax = 0xD547CBE0748CAD80
rbx += rax

rbx = ror(rbx,0xff&-0x41)
rbx = rol(rbx,0x6E)
rbx = rol(rbx,0x2B)
rbx = ror(rbx,0x39)
rbx = ror(rbx,0x5F)
rax = 0x944CDA5C1FF064FF
rbx -= rax
rax = 0x75CD27F1051C7A87
rbx ^= rax
rax = 0x38AC7ECBF4646CFF
rbx -= rax

rbx = ror(rbx,0xff&-0x3E)
rax = 0x231F03D926A6DFF1
rbx += rax

rbx = ror(rbx,0xff&-0x0A)
rax = 0x04BF601AD28D88A7
rbx += rax
rax = 0xC9E8E4E204AACC48
rbx += rax
rax = 0x1D25AC887B597C40
rbx ^= rax
rax = 0xCC53A0A0A1BFC4AC
rbx ^= rax

rbx = rol(rbx,0x19)
rax = 0xE8F8F4FAB8F43D2C
rbx ^= rax

rbx = rol(rbx,0xff&-0x4E)
rbx = ror(rbx,0xff&-0x5D)
rbx = rol(rbx,0xff&-0x4D)
rax = 0xB2BA032ADF8422F3
rbx += rax

rbx = ror(rbx,0x79)
rax = 0xBEE9A89882D02739
rbx -= rax
rax = 0xDEECEAB57B810E18
rbx += rax
rax = 0x952F5FF694FDD323
rbx ^= rax
rax = 0x833CEBD84D67F1C5
rbx -= rax

rbx = rol(rbx,0xff&-0x7D)
rax = 0x60B84C5041949050
rbx -= rax
rax = 0x5AA53C845F84769E
rbx += rax
rax = 0xE9DDA837E2723C41
rbx -= rax
rax = 0x0E04FE14B8CDB633
rbx -= rax
rax = 0x5E0348EA2A6DC212
rbx -= rax
rax = 0x13FAE6B13C80E904
rbx -= rax

rbx = rol(rbx,0xff&-0x80)
rbx = ror(rbx,0xff&-0x49)
rbx = rol(rbx,0x65)
rbx = ror(rbx,0x3E)
rax = 0xFC2ABFFD267883BC
rbx += rax

rbx = ror(rbx,0x1)
rax = 0x79B22DD8D2227AAA
rbx -= rax
rax = 0x3098B882B3A10E6D
rbx += rax

rbx = rol(rbx,0xff&-0x7E)
rbx = ror(rbx,0xff&-0x44)
rax = 0xBCE78E98E592DE3B
rbx ^= rax
rax = 0xFC74D01591A0E177
rbx -= rax
rax = 0x980129B3AFE54DA2
rbx -= rax
rax = 0x91B8F2E3784E5EE2
rbx += rax
rax = 0x17C100CD5409A609
rbx -= rax
rax = 0xFA4F16EACE59A6DB
rbx -= rax
rax = 0x40EC40A3F91E24CC
rbx ^= rax
rax = 0x11AD30B045D6F372
rbx += rax
rax = 0x519321FFC137FAF8
rbx += rax

rbx = rol(rbx,0xff&-0x22)
rbx = ror(rbx,0x68)
rax = 0x118B324C4CF5F667
rbx ^= rax

rbx = ror(rbx,0xff&-0x3B)
rax = 0xF462A125CD0B87FB
rbx ^= rax
rax = 0x4C9A35B0CBF2D879
rbx += rax
rax = 0x6641C8808BE27717
rbx -= rax
rax = 0xABF1CF02E5EBFB0E
rbx -= rax
rax = 0x3B0E71682F34E2F6
rbx += rax
rax = 0x8A0BC5B0F9FDC126
rbx += rax
rax = 0xCD6261CC363C35F6
rbx += rax
rax = 0xE557E7843E39AD5D
rbx += rax
rax = 0xE8018672E00D4D45
rbx -= rax

rbx = rol(rbx,0xff&-0x72)
rbx = rol(rbx,0x4E)
rbx = ror(rbx,0xff&-0x14)
rax = 0x88224EB7EBCC99B7
rbx -= rax
rax = 0x02447E1E58D4BD71
rbx ^= rax
rax = 0x81481EDE0EA91E22
rbx += rax
rax = 0x35381D56930CA99D
rbx -= rax

rbx = ror(rbx,0x73)
rax = 0x73F8F4ACFB943D4D
rbx ^= rax
rax = 0xE6988394172197E8
rbx += rax

rbx = ror(rbx,0x7B)
rax = 0xB82C34EF05FFC213
rbx += rax

rbx = ror(rbx,0x20)
rax = 0x91BF0075A2C4A3DC
rbx += rax
rax = 0x41F0CCCCD145D604
rbx ^= rax
rax = 0xC3B3BDE63BC2E4AA
rbx ^= rax

rbx = ror(rbx,0x5A)
rbx = rol(rbx,0x30)
rbx = rol(rbx,0x78)
rbx = ror(rbx,0xff&-0x07)
rax = 0x51EE442397DEF92B
rbx -= rax
rax = 0x455242A55B0F56F2
rbx ^= rax
rax = 0xD1AC612E35C44684
rbx ^= rax
rax = 0x08D948CCFE8AECF2
rbx -= rax
rax = 0xC77E1379919D7C89
rbx -= rax
rax = 0x538BA60815CC024D
rbx ^= rax

rbx = rol(rbx,0xff&-0x16)
rax = 0x494AB782CD80BB96
rbx ^= rax

rbx = rol(rbx,0xff&-0x2A)
rax = 0x77671300A5B026B0
rbx += rax

rbx = rol(rbx,0x32)
rax = 0x6BE7E9CC80691C55
rbx += rax
rax = 0xF0CEBC58654DB9DD
rbx ^= rax
rax = 0x8ED498F1E608F1EF
rbx -= rax

rbx = ror(rbx,0xff&-0x7D)
rax = 0x53B6C0AF63931AA2
rbx ^= rax
rax = 0x45C94DA977F90AD9
rbx ^= rax

rbx = ror(rbx,0x2C)
rbx = rol(rbx,0x5C)
rbx = rol(rbx,0x16)
rax = 0x09A142C19EE9FDA0
rbx -= rax
rax = 0xC649777348E6D168
rbx += rax
rax = 0xEAD163347CABA509
rbx ^= rax
rax = 0x8E870E0734882040
rbx += rax
rax = 0x5AE9C966C09E815C
rbx ^= rax

rbx = rol(rbx,0x78)
rax = 0x045440DE34B73F56
rbx -= rax
rax = 0x053AF4C2F263D50E
rbx -= rax

rbx = rol(rbx,0x19)
rbx = ror(rbx,0xff&-0x50)
rbx = rol(rbx,0x7A)
rbx = rol(rbx,0x0D)
rbx = rol(rbx,0x0F)
rbx = rol(rbx,0x65)
rax = 0xCF1C6661AF02C44F
rbx ^= rax
rax = 0xD9179584E86BA1B0
rbx += rax

rbx = ror(rbx,0xff&-0x2C)
rbx = rol(rbx,0xff&-0x3B)
rbx = ror(rbx,0xff&-0x62)
rax = 0x54FD1AA9653DB63C
rbx ^= rax
rax = 0x39B9F1E4DC691DF6
rbx += rax

rbx = ror(rbx,0xff&-0x21)
rax = 0xBB43B68EDFC8AADD
rbx += rax
rax = 0x412B1619AEC9ECE4
rbx -= rax
rax = 0xBF0F6EC058DB596C
rbx ^= rax

rbx = rol(rbx,0x3E)
rax = 0x82498C880B83D24F
rbx ^= rax
rax = 0xF2563F245C76CA8B
rbx -= rax
rax = 0x6E17A59E44F3327C
rbx -= rax
rax = 0x4FBE75893045CEC8
rbx -= rax
rax = 0x0F8C2F037D9ABD6B
rbx -= rax
rax = 0x700BEED421A7757F
rbx -= rax
rax = 0x1C1604B2D1662F69
rbx ^= rax

rbx = ror(rbx,0x76)
rax = 0x5CCBCE542A483A4F
rbx += rax
rax = 0x5C651C61A0DDFA94
rbx ^= rax
rax = 0x2C0F1EDAD880F8DE
rbx -= rax

rbx = rol(rbx,0xff&-0x58)
rax = 0xC4FA83FFEB140039
rbx += rax
rax = 0xB7283A2CD1789BEB
rbx += rax
rax = 0xF31B82438D597263
rbx -= rax

rbx = rol(rbx,0x26)
rbx = ror(rbx,0x1C)
rax = 0xE9E431AE1696BA51
rbx -= rax
rax = 0xD9C337A4DAD0F146
rbx += rax
rax = 0x263FD0FA3424549D
rbx += rax
rax = 0xCB354A8AC06DC55F
rbx -= rax
rax = 0xB65B8DFE2D5F2284
rbx += rax
rax = 0xEC981E3CD73B0322
rbx -= rax
rax = 0x22490F206CDCF726
rbx -= rax
rax = 0xF28F90C23FE4192A
rbx ^= rax
rax = 0x6E525D79E84976E5
rbx -= rax

rbx = ror(rbx,0xff&-0x1B)
rax = 0x41DF9FE6310181F9
rbx -= rax

rbx = ror(rbx,0x48)
rbx = rol(rbx,0xff&-0x2A)
rax = 0x0D9F06A6EF4B9A35
rbx -= rax
rax = 0x0B86DBE0889F73D5
rbx ^= rax
rax = 0xE43D571F7C46205C
rbx -= rax
rax = 0xA5EEDADA7BF9C3FF
rbx += rax
rax = 0x8CE56B1BB027E045
rbx -= rax
rax = 0xE95DBA66D80EB176
rbx += rax
rax = 0xAD0C9AE2A10FC74E
rbx -= rax

rbx = rol(rbx,0xff&-0x0B)
rax = 0x05DE46B623C3D1BA
rbx -= rax
rax = 0x6F6A0DEF398E0698
rbx ^= rax
rax = 0x9C47144037C1A714
rbx += rax

rbx = rol(rbx,0xff&-0x38)
rax = 0xE2D5F00AD51FEA34
rbx -= rax
rax = 0x70C654270139F11B
rbx ^= rax
rax = 0x601ECFC576CB8C4C
rbx -= rax

rbx = ror(rbx,0x23)
rbx = ror(rbx,0x30)
rax = 0x53E8AC2B1DCEE441
rbx += rax

rbx = rol(rbx,0xff&-0x7E)
rax = 0x0A209D8BA8DB43A1
rbx += rax

rbx = rol(rbx,0xff&-0x27)
rax = 0x21A1FED8AE0CD9D4
rbx += rax

rbx = rol(rbx,0xff&-0x77)
rbx = rol(rbx,0x1)
rax = 0x8F8C0117CFB2AE0B
rbx -= rax

rbx = rol(rbx,0x54)
rax = 0x85C541919EC79D22
rbx -= rax
rax = 0x08B5AF765B7B46DC
rbx -= rax
rax = 0x3AB169258D5E25E1
rbx += rax

rbx = rol(rbx,0xff&-0x5D)
rax = 0xE61AF0C2D1832F8B
rbx -= rax
rax = 0xFAC0D83139243F1F
rbx += rax

rbx = rol(rbx,0xff&-0x1F)
rbx = ror(rbx,0x1E)
rbx = ror(rbx,0xff&-0x7D)
rbx = ror(rbx,0x1A)
rbx = ror(rbx,0xff&-0x40)
rax = 0xB42209CA9ED321DD
rbx ^= rax

rbx = ror(rbx,0x50)
rbx = rol(rbx,0x3D)
rbx = rol(rbx,0x3F)
rax = 0x541446CE327044CA
rbx ^= rax
rax = 0x18A4D406897FCC11
rbx += rax
rax = 0x8EEB4EBA18F73F1C
rbx -= rax

rbx = rol(rbx,0xff&-0x53)
rax = 0x2042C9D6FE11F1AA
rbx ^= rax

rbx = rol(rbx,0xff&-0x07)
rax = 0xC615340673F8A933
rbx ^= rax
rax = 0x14FD4B553E86BFCA
rbx ^= rax
rax = 0x099B5DC021E38318
rbx -= rax

rbx = ror(rbx,0x52)
rbx = ror(rbx,0x2C)
rax = 0xF275F6512F76B346
rbx -= rax

rbx = rol(rbx,0xff&-0x4A)
rax = 0xFC2D66405D641581
rbx -= rax
rax = 0xCAB3FF6A51798FCF
rbx -= rax

rbx = ror(rbx,0xff&-0x60)
rbx = rol(rbx,0xff&-0x55)
rbx = rol(rbx,0xff&-0x0A)
rax = 0xD6790391CD863E58
rbx ^= rax
rax = 0xD9C777752F8622CC
rbx ^= rax

rbx = ror(rbx,0x57)
rbx = rol(rbx,0x34)
rax = 0xEDB94D0C0CF85D13
rbx += rax
rax = 0x3D351578B4AD3395
rbx -= rax

rbx = ror(rbx,0x22)
rax = 0xDDF9FB1EEEA42D00
rbx += rax
rbx = ror(rbx,0xff&-0x59)

print hex(rbx)
