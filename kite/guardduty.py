from botocore.exceptions import ClientError


def get_detectors(session, region) -> list[dict]:
    client = session.client("guardduty", region_name=region)
    try:
        paginator = client.get_paginator("list_detectors")
        detectors = []
        for page in paginator.paginate():
            for detector_id in page["DetectorIds"]:
                detector = client.get_detector(DetectorId=detector_id)
                detectors.append(
                    dict(
                        DetectorId=detector_id,
                        Status=detector["Status"],
                        CreatedAt=detector["CreatedAt"],
                        UpdatedAt=detector["UpdatedAt"],
                        FindingPublishingFrequency=detector[
                            "FindingPublishingFrequency"
                        ],
                        DataSources=detector["DataSources"],
                        Features=detector["Features"],
                    )
                )
        return detectors
    except ClientError as e:
        if e.response["Error"]["Code"] == "SubscriptionRequiredException":
            return []
        raise e
