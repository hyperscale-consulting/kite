from collections import defaultdict

from botocore.exceptions import ClientError

from hyperscale.kite.detective import get_graphs


class DetectiveClient:
    def __init__(self, error_code=None):
        self.error_response = error_code and {"Error": {"Code": error_code}} or None
        self.error_code = error_code
        self.graphs = []
        self.members = defaultdict(list)

    def list_graphs(self):
        if self.error_response:
            raise ClientError(self.error_response, "ListGraphs")

        return {"GraphList": self.graphs}

    def list_members(self, GraphArn):
        return {"MemberDetails": self.members[GraphArn]}

    def add_graph(self, arn):
        self.graphs.append(
            {
                "Arn": arn,
            }
        )

    def add_member(self, graph_arn, account_id):
        self.members[graph_arn].append(
            {
                "AccountId": account_id,
                "GraphArn": graph_arn,
            }
        )


def test_get_graphs(stub_aws_session):
    client = DetectiveClient()
    stub_aws_session.register_client(client, "detective", "eu-west-2")
    graph_arn = (
        "arn:aws:detective:eu-west-2:123456789012:graph:"
        "a1b2c3d4-5678-90ab-cdef-123456789012"
    )
    account_id = "123456789012"
    client.add_graph(graph_arn)
    client.add_member(graph_arn=graph_arn, account_id=account_id)
    graphs = get_graphs(session=stub_aws_session, region="eu-west-2")
    assert len(graphs) == 1
    graph = graphs[0]
    assert graph["Arn"] == graph_arn
    members = graph["Members"]
    assert isinstance(members, list)
    assert len(members) == 1
    assert members[0]["AccountId"] == account_id


def test_get_graphs_no_subscription(stub_aws_session):
    client = DetectiveClient(error_code="SubscriptionRequiredException")
    stub_aws_session.register_client(client, "detective", "eu-west-2")
    graphs = get_graphs(session=stub_aws_session, region="eu-west-2")
    assert len(graphs) == 0
