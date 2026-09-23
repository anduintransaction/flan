import re

from requests import Session, HTTPError

from contrib.descriptions import VulnDescriptionProvider, VulnDescription

__all__ = ['CveProjectProvider']


class CveProjectProvider(VulnDescriptionProvider):
    """
    Provides vulnerability descriptions using requests to CVEProject (CVE JSON 5 format)
    """
    uri_template = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{}/{}/{}.json'
    nist_uri_template = 'https://nvd.nist.gov/vuln/detail/{}'
    cve_id_pattern = re.compile(r'^CVE-(\d{4})-(\d{4,})$')

    def __init__(self, session: Session):
        self.sess = session
        self.cache = {}

    @staticmethod
    def _extract_description(cve_json: dict) -> str:
        cna = cve_json['containers']['cna']
        # Rejected CVEs carry rejectedReasons instead of descriptions
        entries = cna.get('descriptions') or cna.get('rejectedReasons') or []
        if not entries:
            raise ValueError('no descriptions found in CVE record')
        for entry in entries:
            if entry.get('lang', '').lower().startswith('en'):
                return entry['value']
        return entries[0]['value']

    def get_description(self, vuln: str, vuln_type: str) -> VulnDescription:
        if vuln in self.cache:
            return self.cache[vuln]

        if vuln_type != 'cve':
            return VulnDescription('', '')

        match = self.cve_id_pattern.match(vuln.strip().upper())
        if match is None:
            return VulnDescription('', 'Description fetching error: malformed CVE id ' + repr(vuln))

        cve_id = match.group(0)
        year, number = match.group(1), match.group(2)
        section = number[:-3] + 'xxx'
        url = self.uri_template.format(year, section, cve_id)

        try:
            response = self.sess.get(url)
            response.raise_for_status()
            description = self._extract_description(response.json())
        except HTTPError as he:
            return VulnDescription('', 'Description fetching error: ' + str(he))
        except (KeyError, IndexError, TypeError, ValueError) as e:
            return VulnDescription('', 'Description parsing error for {}: {!r}'.format(url, e))

        vuln_description = VulnDescription(description, self.nist_uri_template.format(cve_id))
        self.cache[vuln] = vuln_description
        return vuln_description
