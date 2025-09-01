from rest_framework import serializers


class SigningRequestSerializer(serializers.Serializer):
    signing_profile = serializers.CharField(required=True)
    description = serializers.CharField(required=False)
    url = serializers.URLField(required=False)
    response_type = serializers.ChoiceField(
        choices=["complete", "pkcs7"], default="complete"
    )

    def get_fields(self):
        fields = super().get_fields()
        fields["signing-profile"] = fields.pop("signing_profile")
        fields["response-type"] = fields.pop("response_type")
        return fields
