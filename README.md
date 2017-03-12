### StripeFraudRules
##### Rules for Stripe Radar to decrease Credit Card fraud and chargebacks
I run payments for my app through Stripe - and it has pretty average fraud detection messages. Out of 8 of my chargebacks, Stripe Radar has identified each transaction as `normal`.

Here are some rules to help cut back on Credit Card fraud on Stripe - to implement them:
- Go to your Stripe Dashboard > Radar > Rules [(Direct Link)](https://dashboard.stripe.com/fraud/rules)
- Click the **'Add Rule'** button bellow either 'when should a payment be **blocked**' (automatically blocks all transactions matching the rule) OR 'when should a payment be **placed in review**' (doesn't complete the transaction, instead places it in a queue for manual review by yourself) 
- Copy and paste the rule (without the `//comments`) into the window that appears, then test and apply the rule.
![Stripe Screenshot](http://i.imgur.com/WTaR0cf.png)

I hope these rules help you prevent chargebacks - I'll be adding new rules as they come to hand, if you have any techniques to add feel free to update and make a pull request

```php
/*
		      ANONYMOUS IP
Block if payment attempt comes from a known
       proxy or tor node IP address
*/

:is_anonymous_ip:

/*
   IP/CARD COUNTRY MISMATCH - STRICT BLOCK   
  Blocks all transactions where IP and Card 
 country don't match - very strict, use with
                 caution.
  Ideal if you have high rates of fraud and
   don't mind missing a few payments if it
           means less chargebacks.
*/

:ip_country: != :card_country:

/*
  IP/CARD COUNTRY MISMATCH - TOP 22 COUNTRIES
    List of rules to block IP/Card Country       
  mismatch in top 22 most fraudulent countries
         according to getcontrol.co
*/

:ip_country: = 'LV' and :card_country: != 'LV'   //Latvia
:ip_country: = 'EG' and :card_country: != 'EG'   //Egypt
:ip_country: = 'US' and :card_country: != 'US'   //United States
:ip_country: = 'MX' and :card_country: != 'MX'   //Mexico
:ip_country: = 'UA' and :card_country: != 'UA'   //Ukraine
:ip_country: = 'HU' and :card_country: != 'HU'   //Hungary
:ip_country: = 'MY' and :card_country: != 'MY'   //Malaysia
:ip_country: = 'CO' and :card_country: != 'CO'   //Colombia
:ip_country: = 'RO' and :card_country: != 'RO'   //Romania
:ip_country: = 'PH' and :card_country: != 'PH'   //Philippines

/*
  IP/CARD COUNTRY MISMATCH - ALL COUNTRIES LIST
   Pick and choose from this list if you have
  any particular countries you're having fraud
               difficulties with.
*/

:ip_country: = 'AF' and :card_country: != 'AF'   //Afghanistan
:ip_country: = 'AX' and :card_country: != 'AX'   //Aland Islands
:ip_country: = 'AL' and :card_country: != 'AL'   //Albania
:ip_country: = 'DZ' and :card_country: != 'DZ'   //Algeria
:ip_country: = 'AS' and :card_country: != 'AS'   //American Samoa
:ip_country: = 'AD' and :card_country: != 'AD'   //Andorra
:ip_country: = 'AO' and :card_country: != 'AO'   //Angola
:ip_country: = 'AI' and :card_country: != 'AI'   //Anguilla
:ip_country: = 'AQ' and :card_country: != 'AQ'   //Antarctica
:ip_country: = 'AG' and :card_country: != 'AG'   //Antigua And Barbuda
:ip_country: = 'AR' and :card_country: != 'AR'   //Argentina
:ip_country: = 'AM' and :card_country: != 'AM'   //Armenia
:ip_country: = 'AW' and :card_country: != 'AW'   //Aruba
:ip_country: = 'AU' and :card_country: != 'AU'   //Australia
:ip_country: = 'AT' and :card_country: != 'AT'   //Austria
:ip_country: = 'AZ' and :card_country: != 'AZ'   //Azerbaijan
:ip_country: = 'BS' and :card_country: != 'BS'   //Bahamas
:ip_country: = 'BH' and :card_country: != 'BH'   //Bahrain
:ip_country: = 'BD' and :card_country: != 'BD'   //Bangladesh
:ip_country: = 'BB' and :card_country: != 'BB'   //Barbados
:ip_country: = 'BY' and :card_country: != 'BY'   //Belarus
:ip_country: = 'BE' and :card_country: != 'BE'   //Belgium
:ip_country: = 'BZ' and :card_country: != 'BZ'   //Belize
:ip_country: = 'BJ' and :card_country: != 'BJ'   //Benin
:ip_country: = 'BM' and :card_country: != 'BM'   //Bermuda
:ip_country: = 'BT' and :card_country: != 'BT'   //Bhutan
:ip_country: = 'BO' and :card_country: != 'BO'   //Bolivia
:ip_country: = 'BA' and :card_country: != 'BA'   //Bosnia And Herzegovina
:ip_country: = 'BW' and :card_country: != 'BW'   //Botswana
:ip_country: = 'BV' and :card_country: != 'BV'   //Bouvet Island
:ip_country: = 'BR' and :card_country: != 'BR'   //Brazil
:ip_country: = 'IO' and :card_country: != 'IO'   //British Indian Ocean Territory
:ip_country: = 'BN' and :card_country: != 'BN'   //Brunei Darussalam
:ip_country: = 'BG' and :card_country: != 'BG'   //Bulgaria
:ip_country: = 'BF' and :card_country: != 'BF'   //Burkina Faso
:ip_country: = 'BI' and :card_country: != 'BI'   //Burundi
:ip_country: = 'KH' and :card_country: != 'KH'   //Cambodia
:ip_country: = 'CM' and :card_country: != 'CM'   //Cameroon
:ip_country: = 'CA' and :card_country: != 'CA'   //Canada
:ip_country: = 'CV' and :card_country: != 'CV'   //Cape Verde
:ip_country: = 'KY' and :card_country: != 'KY'   //Cayman Islands
:ip_country: = 'CF' and :card_country: != 'CF'   //Central African Republic
:ip_country: = 'TD' and :card_country: != 'TD'   //Chad
:ip_country: = 'CL' and :card_country: != 'CL'   //Chile
:ip_country: = 'CN' and :card_country: != 'CN'   //China
:ip_country: = 'CX' and :card_country: != 'CX'   //Christmas Island
:ip_country: = 'CC' and :card_country: != 'CC'   //Cocos (Keeling) Islands
:ip_country: = 'CO' and :card_country: != 'CO'   //Colombia
:ip_country: = 'KM' and :card_country: != 'KM'   //Comoros
:ip_country: = 'CG' and :card_country: != 'CG'   //Congo
:ip_country: = 'CD' and :card_country: != 'CD'   //Congo, Democratic Republic
:ip_country: = 'CK' and :card_country: != 'CK'   //Cook Islands
:ip_country: = 'CR' and :card_country: != 'CR'   //Costa Rica
:ip_country: = 'CI' and :card_country: != 'CI'   //Cote D'Ivoire
:ip_country: = 'HR' and :card_country: != 'HR'   //Croatia
:ip_country: = 'CU' and :card_country: != 'CU'   //Cuba
:ip_country: = 'CY' and :card_country: != 'CY'   //Cyprus
:ip_country: = 'CZ' and :card_country: != 'CZ'   //Czech Republic
:ip_country: = 'DK' and :card_country: != 'DK'   //Denmark
:ip_country: = 'DJ' and :card_country: != 'DJ'   //Djibouti
:ip_country: = 'DM' and :card_country: != 'DM'   //Dominica
:ip_country: = 'DO' and :card_country: != 'DO'   //Dominican Republic
:ip_country: = 'EC' and :card_country: != 'EC'   //Ecuador
:ip_country: = 'EG' and :card_country: != 'EG'   //Egypt
:ip_country: = 'SV' and :card_country: != 'SV'   //El Salvador
:ip_country: = 'GQ' and :card_country: != 'GQ'   //Equatorial Guinea
:ip_country: = 'ER' and :card_country: != 'ER'   //Eritrea
:ip_country: = 'EE' and :card_country: != 'EE'   //Estonia
:ip_country: = 'ET' and :card_country: != 'ET'   //Ethiopia
:ip_country: = 'FK' and :card_country: != 'FK'   //Falkland Islands (Malvinas)
:ip_country: = 'FO' and :card_country: != 'FO'   //Faroe Islands
:ip_country: = 'FJ' and :card_country: != 'FJ'   //Fiji
:ip_country: = 'FI' and :card_country: != 'FI'   //Finland
:ip_country: = 'FR' and :card_country: != 'FR'   //France
:ip_country: = 'GF' and :card_country: != 'GF'   //French Guiana
:ip_country: = 'PF' and :card_country: != 'PF'   //French Polynesia
:ip_country: = 'TF' and :card_country: != 'TF'   //French Southern Territories
:ip_country: = 'GA' and :card_country: != 'GA'   //Gabon
:ip_country: = 'GM' and :card_country: != 'GM'   //Gambia
:ip_country: = 'GE' and :card_country: != 'GE'   //Georgia
:ip_country: = 'DE' and :card_country: != 'DE'   //Germany
:ip_country: = 'GH' and :card_country: != 'GH'   //Ghana
:ip_country: = 'GI' and :card_country: != 'GI'   //Gibraltar
:ip_country: = 'GR' and :card_country: != 'GR'   //Greece
:ip_country: = 'GL' and :card_country: != 'GL'   //Greenland
:ip_country: = 'GD' and :card_country: != 'GD'   //Grenada
:ip_country: = 'GP' and :card_country: != 'GP'   //Guadeloupe
:ip_country: = 'GU' and :card_country: != 'GU'   //Guam
:ip_country: = 'GT' and :card_country: != 'GT'   //Guatemala
:ip_country: = 'GG' and :card_country: != 'GG'   //Guernsey
:ip_country: = 'GN' and :card_country: != 'GN'   //Guinea
:ip_country: = 'GW' and :card_country: != 'GW'   //Guinea-Bissau
:ip_country: = 'GY' and :card_country: != 'GY'   //Guyana
:ip_country: = 'HT' and :card_country: != 'HT'   //Haiti
:ip_country: = 'HM' and :card_country: != 'HM'   //Heard Island & Mcdonald Islands
:ip_country: = 'VA' and :card_country: != 'VA'   //Holy See (Vatican City State)
:ip_country: = 'HN' and :card_country: != 'HN'   //Honduras
:ip_country: = 'HK' and :card_country: != 'HK'   //Hong Kong
:ip_country: = 'HU' and :card_country: != 'HU'   //Hungary
:ip_country: = 'IS' and :card_country: != 'IS'   //Iceland
:ip_country: = 'IN' and :card_country: != 'IN'   //India
:ip_country: = 'ID' and :card_country: != 'ID'   //Indonesia
:ip_country: = 'IR' and :card_country: != 'IR'   //Iran, Islamic Republic Of
:ip_country: = 'IQ' and :card_country: != 'IQ'   //Iraq
:ip_country: = 'IE' and :card_country: != 'IE'   //Ireland
:ip_country: = 'IM' and :card_country: != 'IM'   //Isle Of Man
:ip_country: = 'IL' and :card_country: != 'IL'   //Israel
:ip_country: = 'IT' and :card_country: != 'IT'   //Italy
:ip_country: = 'JM' and :card_country: != 'JM'   //Jamaica
:ip_country: = 'JP' and :card_country: != 'JP'   //Japan
:ip_country: = 'JE' and :card_country: != 'JE'   //Jersey
:ip_country: = 'JO' and :card_country: != 'JO'   //Jordan
:ip_country: = 'KZ' and :card_country: != 'KZ'   //Kazakhstan
:ip_country: = 'KE' and :card_country: != 'KE'   //Kenya
:ip_country: = 'KI' and :card_country: != 'KI'   //Kiribati
:ip_country: = 'KR' and :card_country: != 'KR'   //Korea
:ip_country: = 'KW' and :card_country: != 'KW'   //Kuwait
:ip_country: = 'KG' and :card_country: != 'KG'   //Kyrgyzstan
:ip_country: = 'LA' and :card_country: != 'LA'   //Lao People's Democratic Republic
:ip_country: = 'LV' and :card_country: != 'LV'   //Latvia
:ip_country: = 'LB' and :card_country: != 'LB'   //Lebanon
:ip_country: = 'LS' and :card_country: != 'LS'   //Lesotho
:ip_country: = 'LR' and :card_country: != 'LR'   //Liberia
:ip_country: = 'LY' and :card_country: != 'LY'   //Libyan Arab Jamahiriya
:ip_country: = 'LI' and :card_country: != 'LI'   //Liechtenstein
:ip_country: = 'LT' and :card_country: != 'LT'   //Lithuania
:ip_country: = 'LU' and :card_country: != 'LU'   //Luxembourg
:ip_country: = 'MO' and :card_country: != 'MO'   //Macao
:ip_country: = 'MK' and :card_country: != 'MK'   //Macedonia
:ip_country: = 'MG' and :card_country: != 'MG'   //Madagascar
:ip_country: = 'MW' and :card_country: != 'MW'   //Malawi
:ip_country: = 'MY' and :card_country: != 'MY'   //Malaysia
:ip_country: = 'MV' and :card_country: != 'MV'   //Maldives
:ip_country: = 'ML' and :card_country: != 'ML'   //Mali
:ip_country: = 'MT' and :card_country: != 'MT'   //Malta
:ip_country: = 'MH' and :card_country: != 'MH'   //Marshall Islands
:ip_country: = 'MQ' and :card_country: != 'MQ'   //Martinique
:ip_country: = 'MR' and :card_country: != 'MR'   //Mauritania
:ip_country: = 'MU' and :card_country: != 'MU'   //Mauritius
:ip_country: = 'YT' and :card_country: != 'YT'   //Mayotte
:ip_country: = 'MX' and :card_country: != 'MX'   //Mexico
:ip_country: = 'FM' and :card_country: != 'FM'   //Micronesia, Federated States Of
:ip_country: = 'MD' and :card_country: != 'MD'   //Moldova
:ip_country: = 'MC' and :card_country: != 'MC'   //Monaco
:ip_country: = 'MN' and :card_country: != 'MN'   //Mongolia
:ip_country: = 'ME' and :card_country: != 'ME'   //Montenegro
:ip_country: = 'MS' and :card_country: != 'MS'   //Montserrat
:ip_country: = 'MA' and :card_country: != 'MA'   //Morocco
:ip_country: = 'MZ' and :card_country: != 'MZ'   //Mozambique
:ip_country: = 'MM' and :card_country: != 'MM'   //Myanmar
:ip_country: = 'NA' and :card_country: != 'NA'   //Namibia
:ip_country: = 'NR' and :card_country: != 'NR'   //Nauru
:ip_country: = 'NP' and :card_country: != 'NP'   //Nepal
:ip_country: = 'NL' and :card_country: != 'NL'   //Netherlands
:ip_country: = 'AN' and :card_country: != 'AN'   //Netherlands Antilles
:ip_country: = 'NC' and :card_country: != 'NC'   //New Caledonia
:ip_country: = 'NZ' and :card_country: != 'NZ'   //New Zealand
:ip_country: = 'NI' and :card_country: != 'NI'   //Nicaragua
:ip_country: = 'NE' and :card_country: != 'NE'   //Niger
:ip_country: = 'NG' and :card_country: != 'NG'   //Nigeria
:ip_country: = 'NU' and :card_country: != 'NU'   //Niue
:ip_country: = 'NF' and :card_country: != 'NF'   //Norfolk Island
:ip_country: = 'MP' and :card_country: != 'MP'   //Northern Mariana Islands
:ip_country: = 'NO' and :card_country: != 'NO'   //Norway
:ip_country: = 'OM' and :card_country: != 'OM'   //Oman
:ip_country: = 'PK' and :card_country: != 'PK'   //Pakistan
:ip_country: = 'PW' and :card_country: != 'PW'   //Palau
:ip_country: = 'PS' and :card_country: != 'PS'   //Palestinian Territory, Occupied
:ip_country: = 'PA' and :card_country: != 'PA'   //Panama
:ip_country: = 'PG' and :card_country: != 'PG'   //Papua New Guinea
:ip_country: = 'PY' and :card_country: != 'PY'   //Paraguay
:ip_country: = 'PE' and :card_country: != 'PE'   //Peru
:ip_country: = 'PH' and :card_country: != 'PH'   //Philippines
:ip_country: = 'PN' and :card_country: != 'PN'   //Pitcairn
:ip_country: = 'PL' and :card_country: != 'PL'   //Poland
:ip_country: = 'PT' and :card_country: != 'PT'   //Portugal
:ip_country: = 'PR' and :card_country: != 'PR'   //Puerto Rico
:ip_country: = 'QA' and :card_country: != 'QA'   //Qatar
:ip_country: = 'RE' and :card_country: != 'RE'   //Reunion
:ip_country: = 'RO' and :card_country: != 'RO'   //Romania
:ip_country: = 'RU' and :card_country: != 'RU'   //Russian Federation
:ip_country: = 'RW' and :card_country: != 'RW'   //Rwanda
:ip_country: = 'BL' and :card_country: != 'BL'   //Saint Barthelemy
:ip_country: = 'SH' and :card_country: != 'SH'   //Saint Helena
:ip_country: = 'KN' and :card_country: != 'KN'   //Saint Kitts And Nevis
:ip_country: = 'LC' and :card_country: != 'LC'   //Saint Lucia
:ip_country: = 'MF' and :card_country: != 'MF'   //Saint Martin
:ip_country: = 'PM' and :card_country: != 'PM'   //Saint Pierre And Miquelon
:ip_country: = 'VC' and :card_country: != 'VC'   //Saint Vincent And Grenadines
:ip_country: = 'WS' and :card_country: != 'WS'   //Samoa
:ip_country: = 'SM' and :card_country: != 'SM'   //San Marino
:ip_country: = 'ST' and :card_country: != 'ST'   //Sao Tome And Principe
:ip_country: = 'SA' and :card_country: != 'SA'   //Saudi Arabia
:ip_country: = 'SN' and :card_country: != 'SN'   //Senegal
:ip_country: = 'RS' and :card_country: != 'RS'   //Serbia
:ip_country: = 'SC' and :card_country: != 'SC'   //Seychelles
:ip_country: = 'SL' and :card_country: != 'SL'   //Sierra Leone
:ip_country: = 'SG' and :card_country: != 'SG'   //Singapore
:ip_country: = 'SK' and :card_country: != 'SK'   //Slovakia
:ip_country: = 'SI' and :card_country: != 'SI'   //Slovenia
:ip_country: = 'SB' and :card_country: != 'SB'   //Solomon Islands
:ip_country: = 'SO' and :card_country: != 'SO'   //Somalia
:ip_country: = 'ZA' and :card_country: != 'ZA'   //South Africa
:ip_country: = 'GS' and :card_country: != 'GS'   //South Georgia And Sandwich Isl.
:ip_country: = 'ES' and :card_country: != 'ES'   //Spain
:ip_country: = 'LK' and :card_country: != 'LK'   //Sri Lanka
:ip_country: = 'SD' and :card_country: != 'SD'   //Sudan
:ip_country: = 'SR' and :card_country: != 'SR'   //Suriname
:ip_country: = 'SJ' and :card_country: != 'SJ'   //Svalbard And Jan Mayen
:ip_country: = 'SZ' and :card_country: != 'SZ'   //Swaziland
:ip_country: = 'SE' and :card_country: != 'SE'   //Sweden
:ip_country: = 'CH' and :card_country: != 'CH'   //Switzerland
:ip_country: = 'SY' and :card_country: != 'SY'   //Syrian Arab Republic
:ip_country: = 'TW' and :card_country: != 'TW'   //Taiwan
:ip_country: = 'TJ' and :card_country: != 'TJ'   //Tajikistan
:ip_country: = 'TZ' and :card_country: != 'TZ'   //Tanzania
:ip_country: = 'TH' and :card_country: != 'TH'   //Thailand
:ip_country: = 'TL' and :card_country: != 'TL'   //Timor-Leste
:ip_country: = 'TG' and :card_country: != 'TG'   //Togo
:ip_country: = 'TK' and :card_country: != 'TK'   //Tokelau
:ip_country: = 'TO' and :card_country: != 'TO'   //Tonga
:ip_country: = 'TT' and :card_country: != 'TT'   //Trinidad And Tobago
:ip_country: = 'TN' and :card_country: != 'TN'   //Tunisia
:ip_country: = 'TR' and :card_country: != 'TR'   //Turkey
:ip_country: = 'TM' and :card_country: != 'TM'   //Turkmenistan
:ip_country: = 'TC' and :card_country: != 'TC'   //Turks And Caicos Islands
:ip_country: = 'TV' and :card_country: != 'TV'   //Tuvalu
:ip_country: = 'UG' and :card_country: != 'UG'   //Uganda
:ip_country: = 'UA' and :card_country: != 'UA'   //Ukraine
:ip_country: = 'AE' and :card_country: != 'AE'   //United Arab Emirates
:ip_country: = 'GB' and :card_country: != 'GB'   //United Kingdom
:ip_country: = 'US' and :card_country: != 'US'   //United States
:ip_country: = 'UM' and :card_country: != 'UM'   //United States Outlying Islands
:ip_country: = 'UY' and :card_country: != 'UY'   //Uruguay
:ip_country: = 'UZ' and :card_country: != 'UZ'   //Uzbekistan
:ip_country: = 'VU' and :card_country: != 'VU'   //Vanuatu
:ip_country: = 'VE' and :card_country: != 'VE'   //Venezuela
:ip_country: = 'VN' and :card_country: != 'VN'   //Viet Nam
:ip_country: = 'VG' and :card_country: != 'VG'   //Virgin Islands, British
:ip_country: = 'VI' and :card_country: != 'VI'   //Virgin Islands, U.S.
:ip_country: = 'WF' and :card_country: != 'WF'   //Wallis And Futuna
:ip_country: = 'EH' and :card_country: != 'EH'   //Western Sahara
:ip_country: = 'YE' and :card_country: != 'YE'   //Yemen
:ip_country: = 'ZM' and :card_country: != 'ZM'   //Zambia
:ip_country: = 'ZW' and :card_country: != 'ZW'   //Zimbabwe
```
