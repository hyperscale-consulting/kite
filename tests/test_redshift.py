from botocore.exceptions import ClientError

from hyperscale.kite.redshift import get_clusters


class RedshiftClient:
    def __init__(self, error_code=None):
        self.error_response = error_code and {"Error": {"Code": error_code}} or None
        self.clusters = []

    def describe_clusters(self):
        if self.error_response:
            raise ClientError(self.error_response, "DescribeClusters")
        return {"Clusters": self.clusters}

    def add_cluster(self, cluster_id: str):
        self.clusters.append({"ClusterIdentifier": cluster_id})


def test_get_clusters(stub_aws_session):
    client = RedshiftClient()
    client.add_cluster("test-cluster-1")
    stub_aws_session.register_client(client, "redshift", region_name="us-west-2")
    clusters = get_clusters(session=stub_aws_session, region="us-west-2")
    assert len(clusters) == 1
    assert clusters[0]["ClusterIdentifier"] == "test-cluster-1"


def test_get_clusters_no_sub(stub_aws_session):
    client = RedshiftClient(error_code="OptInRequired")
    stub_aws_session.register_client(client, "redshift", region_name="us-west-2")
    clusters = get_clusters(session=stub_aws_session, region="us-west-2")
    assert len(clusters) == 0
