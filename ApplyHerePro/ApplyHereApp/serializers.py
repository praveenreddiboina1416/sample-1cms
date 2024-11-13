from rest_framework import serializers
from .models import User
from rest_framework_simplejwt.tokens import RefreshToken, TokenError



class RegistrationSerializer(serializers.ModelSerializer):
  # We are writing this becoz we need confirm password field in our Registratin Request
  password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
  class Meta:
    model = User
    fields=['email', 'name', 'password', 'password2','role']
    extra_kwargs={
      'password':{'write_only':True}
    }

  # Validating Password and Confirm Password while Registration
  def validate(self, attrs):
    password = attrs.get('password')
    password2 = attrs.get('password2')
    if password != password2:
      raise serializers.ValidationError("Password and Confirm Password doesn't match")
    return attrs

  def create(self, validate_data):
    role = validate_data.pop('role', None)
    return User.objects.create_user(**validate_data, role=role)

class LoginSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(max_length=200)
  class Meta:
    model = User
    fields = ['email','password']

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs
    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')

class ProfileSerializer(serializers.ModelSerializer):
  class Meta:
    model = User
    fields = ['id', 'email', 'name','role']



#addinng crew ---------------------------------------------------

# serializers.py
from rest_framework import serializers
from .models import Crew

class CrewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Crew
        fields = ['id', 'name', 'crew_id', 'is_available']
        read_only_fields = ['crew_id']  # Make token_no read-only since it’s auto-generated



#adding job-----------------------------------------------

# serializers.py
from rest_framework import serializers
from .models import Job, Crew, CrewJobAssignment

class JobSerializer(serializers.ModelSerializer):
    crews = serializers.PrimaryKeyRelatedField(queryset=Crew.objects.all(), many=True)
    #crews = CrewSerializer(source='crews.all', many=True)  # Use
    class Meta:
        model = Job
        fields = ['id', 'job_order_id', 'job_type', 'start_date', 'end_date', 'note', 'crews']

    def create(self, validated_data):
        crews_data = validated_data.pop('crews')
        job = Job.objects.create(**validated_data)
        
        for crew in crews_data:
            # Create a CrewJobAssignment instance to track job count
            CrewJobAssignment.objects.create(job=job, crew=crew)
        
        return job

#-----------daily log---------------------------------------------------
from .models import DailyLog

class DailyLogSerializer(serializers.ModelSerializer):
    job = JobSerializer(read_only=True)  # Nested job details
    crew = CrewSerializer(read_only=True)  # Nested crew details

    class Meta:
        model = DailyLog
        fields = ['id', 'job', 'crew', 'date', 'units_completed', 'work_notes']