> 복습!

# 동원오빠코드

- admin.py

```python
@admin.register(Subject) //
class SubjectAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'description', 'created_at', 'Modified_at')
```

- models.py

```python
class Subject(models.Model):
    id = models.AutoField(db_column="ID", primary_key=True)
    title = models.CharField(db_column="TITLE", max_length=100)
    description = models.TextField(db_column="DESCRIPTION")
    created_at = models.DateTimeField(db_column="CREATED_AT", auto_now_add=True)
    Modified_at = models.DateTimeField(db_column="MODIFIED_AT", auto_now=True)

    def __str__(self):
        return self.title

    class Meta:
        verbose_name = 'subject'
        ordering = ('-created_at',)
```

> - verbose_name :  사람이 보는 이름 for the object. 단수
> - db_column

- views.py

```python
class SubjectViewSet(viewsets.ModelViewSet):
    queryset = Subject.objects.all()
    serializer_class = SubjectSerializer
    pagination_class = PostPageNumberPagination
```

> - pagination_class // 설정에도 있었는데 이렇게 지정 가능하군

- pagination.py

```python
class PostPageNumberPagination(
    	PageNumberPagination):
    page_size = 10
```



# 형선오빠코드

- requirements.txt

```cmd
awsebcli
blessed # for making terminal apps
boto3
botocore
cached-property # for 캐싱
cement
certifi # 네트워크 보안을 담당?
chardet # Universal Character Encoding Detector
colorama # ANSI 관련 ?
coreapi # 문서화 관련. DRF:Schemas
coreschema # ? schema 관련 ?
defusedxml # 다른 패키지 의존성? xml 파싱이라도 하나..
Django
django-cors-headers
django-extensions # 도움을 준다.. db table?
django-rest-framework
django-storages
djangorestframework
djangorestframework-simplejwt
docker
docker-compose
docker-pycreds # ?
dockerpty # ?
docopt # cli 관련 ?
docutils
drf-yasg
future # for scheduling jobs on specified times.
idna # encode ?
inflection # 단수/복수, 카멜,언더
itypes # ?
Jinja2 # 템플릿 엔진 관련
jmespath # json parse 관련
jsonschema # converts Django Forms into JSON Schema
MarkupSafe # safe to use in HTML and XML
oauthlib 
packaging
pathspec # ?
Pillow
psycopg2-binary
PyJWT # encode and decode JSON Web Tokens
pyparsing
python-dateutil # powerful extensions to the standard datetime module
python3-openid
pytx
PyYAML # YAML parser
requests
requests-oauthlib
rest-social-auth
ruamel.yaml # YAML loader/dumper
ruamel.yaml.clib
s3transfer
semantic-version
six # 2 to 3
social-auth-app-django
social-auth-core
sqlparse
swagger-spec-validator
termcolor
texttable
uritemplate # 편리한 uri 생성
urllib3 # python http client
wcwidth # 인코딩 관련 ?
websocket-client
```

- {root}/urls

> - app 관련 url 전체 구조만 파악할거야
> - /account
>   - /  :  UserViewSet
>     - post  -  check/duplication
>     - get  -  self
>     - get  -  self/own/teams
>     - get  -  self/applied/teams
>   - token/  :  SocialTokenObtainAccessView
>   - oauth/github/  :  GithubOauthRedirectView
> - /team
>   - get
>   - post
>   - get  -  comment
>   - get  -  application
> - /tag
> - /comment
> - /application
>   - /
>     - post  -  refuse
>     - post  -  approve

## urls

- accounts/urls

```python
from django.urls import path
from rest_framework import routers
from rest_framework_simplejwt.views import TokenRefreshView
from .views import SocialTokenObtainAccessView, GithubOauthRedirectView, UserViewSet

user_router = routers.SimpleRouter()
user_router.register(r'', UserViewSet)

urlpatterns = [
    path('token/', SocialTokenObtainAccessView.as_view(), name='token_obtain_pair'),
    path('oauth/github/', GithubOauthRedirectView.as_view()),
]

urlpatterns += user_router.urls
```

> - UserViewSet 은 라우터로 등록,
> - SocialTokenObtainAccessView, GithubOauthRedirectView 는 라우터로 등록하지 않은 이유 ?

- applications/urls

```python
from rest_framework import routers
from .views import ApplicationViewSet

router = routers.SimpleRouter()
router.register(r'', ApplicationViewSet)

urlpatterns = []

urlpatterns += router.urls
```



- teams/urls

```python
from rest_framework import routers
from .views import TeamViewSet,TagViewSet,CommentViewSet

team_router = routers.SimpleRouter()
team_router.register(r'', TeamViewSet)
tag_router = routers.SimpleRouter()
tag_router.register(r'',TagViewSet)
comment_router = routers.SimpleRouter()
comment_router.register(r'', CommentViewSet)

rulpatterns = []
```

> 라우터 여럿 만들어두고, 루트 urls 에서 직접 등록했다
>
> 이렇게 해두면 루트 urls 만 찾아보면 전체 구조 보여서 편하겠다!

## models

- accounts

```python
from django.db import models
from django.contrib.auth.models import AbstractUser

class GithubProfile(models.Model):
    login = models.CharField(
        '깃허브 로그인 아이디',max_length=50)
    avatar = models.URLField('아바타')
    email = models.EmailField(
        '이메일',blank=True,null=True)
    languages = models.TextField('언어',blank=True)
    
    def __str__(self):
        return self.login
    
class User(AbstractUser):  
    profile = models.OneToOneField(GithubProfile,
         on_delete=models.SET_NULL,related_name='user',
                                   verbose_name='프로필')
    nickname = models.CharField(
        '별명',max_length=10,blank=True)
    introduction = models.CharField(
        '한 줄 소개',max_length=100,blank=True)
    upload_image = models.ImageField('프로필 사진',
         upload_to='user_image/profile/%Y/%m/%d/',
         blank=True,default='default_user_image.png')
    
    @property
    def is_github_authenticated(self): # 깃헙 로그인인지
        return self.profile_id is not None
    
    @property
    def image(self): # 이미지 경로
        if self.upload_image.name 
        != 'default_user_image.png':
            return self.upload_image.url
        elif self.profile_id is not None:
            return self.profile.avatar
        return self.upload_image.url
```

> - Field 메소드의 '이름' 은 verbose_name 으로 사람이 읽는..
> - is_github_authenticated, image 함수 쓰이는 곳이 없다고..?
>   - 내가 못찾은 건가? 찾는 방법이 틀렸나?
>   - Serializer 에서 fields 로 사용한다!!
> - 외래키_속성 : 이렇게 접근 가능하구남
>   - ImageField 에 name,url 속성이 있구나

- applications

```python
from django.db import models
from django.contrib.auth import get_user_model
from teams.models import Team

User = get_user_model()

class Application(models.Model):
    STATUS_WAITING,STATUS_EXPIRY,STATUS_APPROVED,
    STATUS_REFUSE = "waiting","expiry","approved",
    										"refuse"
    STATUS_CHOICES = (
     (status_waiting,'승인대기'),(STATUS_EXPIRY,'만료'),
     (STATUS_APPROVED,'승인완료'),(STATUS_REFUSE,'승인거절')
    )   
    STATUS_DEFAULT_DISPLAY = '대기중' # 없
    team = models.ForeignKey(Team,verbose_name='팀',related_name='applications',on_delete=models.CASCADE)
    applicant = models.ForeignKey(User,verbose_name='지원자',related_name='applications',on_delete=models.CASCADE)
    reason = models.TextField('지원동기',max_length=200)
    github_account = models.CharField('깃허브계정',max_length=20)
    created_at = models.DateTimeField('생성시각',auto_now_add=True)
    updated_at = models.DateTimeField('수정시각',auto_now=True)
    status = models.CharField('상태',max_length=10,choices=STATUS_CHOICES,default=STATUS_WAITING)
    
    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['team','applicant'], name='unique_application'),
        ]
```

> - models.UniqueConstraint ??

- teams

```python
from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class Tag(models.Model):
    name = modesl.CharField(max_length=10,primary_key=True)
    
    def __str__(self):
        return self.name
    
class Team(models.Model):
    STATUS_WAITING,STATUS_EXPIRY,STATUS_COMPLETE = 'waiting','expiry','complete'
    STATUS_CHOICES = (
    	(STATUS_WAITING,'대기중'),(STATUS_EXPIRY,'만료됨'),
        (STATUS_COMPLETE,'완료됨')
    )
    leader = models.ForeignKey(User,related_name='teams',verbose_name='리더',on_delete=models.CASCADE)
    tags = models.ManyToManyField(Tag,related_name='teams',verbose_name='태그',blank=True)
    title = models.CharField('제목',max_length=20)
    image = models.ImageField('이미지',upload_to='team/image/%Y/%m/%d/',default='default.png')
    objective = models.CharField('목적',max_length=1,blank=True)
    likes = models.ManyToManyField(User,related_name='like_teams',verbose_name="좋아요")
    end_date = modesl.DateTimeField('마감일')
    description = models.TextField('세부설명')
    max_personnel = models.PositiveSmallIntegerField('최대인원')
    created_at = models.DateTimeField('생성시각',auto_now_add=True)
    updated_at = modesl.DateTimeField('수정시각',auto_now=True)
    status = models.CharField('상태',max_length=10,choices=STATUS_CHOICES,default=STATUS_WAITING)
    kakao_chat_url = modesl.URLField()
    
    @property
    def like_count(self):
        like_count = getattr(self,'__like_count',self.likes.count())
        return like_count
        
    @property
    def current_personnel(self):
        current_personnel = self.applications.count() # ?
        return current_personnel
        
    @like_count.setter
    def like_count(self,count):
        self.__like_count = count
    
class Comment(models.Model):
    parent = models.ForeignKey('self',verbose_name='부모댓글',related_name='child_comments',on_delete=models.CASCADE,blank=True,null=True)
    team = models.ForeignKey(Team,verbose_name='팀',related_name='comments',on_delete=models.CASCADE)
    author = models.ForeignKey(User,verbose_name='작성자',related_name='comments',on_delete=modesl.CASCADE)
    body = models.CharField('본문',max_length=300)
    created_at = models.DateTimeField('생성시각',auto_now_add=True)
    updated_at = modes.DateTimeField('수정시각',auto_now=True)
    
    class Meta:
        ordering = ['created_at']
```

> - @like_count.setter
>   - @property:함수 - setter 뭘 봐야 이런 내용 문서 ?
> - likes = ManyToManyField(User,related_name='like_teams'
>   - User 쪽에서 접근하는 이름이 related_name 인가봐!
> - like_count = `getattr(self,'__like_count',self.likes.count())` ??
> - models.ForeignKey('self' ??
>   - 대댓 기능이 있나보지
> - class Team 에 self.applications 가 어디있지?
>   - Application 쪽에 team 이랑 관계가 있긴 한데 이렇게 바로 접근 가능하다고 ?? 헐,,

## serializers

- accounts

```python
from django.contrib.auth import authenticate,get_user_model
from rest_framework import serializers,exceptions
from rest_framework_simplejwt import serializers as jwt_serializer
from rest_framework_wimplejwt.tokens import RefreshToken

User = get_user_model()

class SocialTokenObtainSerializer(jwt_serializer.TokenObtainSerializer):
    
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.fields[self.username_filed] = serializers.CharField(required=False)
        self.fields['password'] = jwt_serializer.PasswordField(required=False)
        self.fields['code'] = serializers.CharField(write_only=True,required=False)
        
    def validate(self,attrs):
        authenticate_kwargs = attrs
        try:
            authenticate_kwargs['request'] = self.context['request']
        except KeyError:
            pass
        
        self.user = authenticate(**authenticate_kwargs)
        if self.user is None or not self.user.is_active:
            raise exceptions.AuthenticationFailed(
            	self.error_messages['no_active_account'],
                'no_active_account',
            )
        return {}    
        
class SocialTokenObtainAccessSerializer(SocialTokenObtainSerializer):
    
    @classmethod
    def get_token(cls,user): # cls ? override
        return RefreshToken.for_user(user)
        
    def validate(self,attrs):
        data = super().validate(attrs)
        refresh = self.get_token(self.user)
        
        data['access'] = str(refresh.access_token)
        data['user_id'] = self.user.id
        data['username'] = self.user.username
        data['is_new'] = False
        
        if not self.user.email and not self.user.nickname:
            data['is_new'] = True
            
        return data
        
class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    upload_image = serializers.ImageField(write_only=True,required=False,use_url=True) # model 의 속성 재정의 ?
    
    class Meta:
        model = User
        fields = ('id','username','password','nickname','email','introduction','image','upload_image','is_github_authenticated')
        
    def create(self,validated_data): # MTM없는데 왜한걸까?
        user = self.Meta.model.objects.create_user(**validated_data)
        return user
```

> - TokenObtainSerializer 을 상속받아서
>   - validate 재정의했는데 다른 함수에는 뭐가 있는지
>   - 어떤 역할을 하는 클래스인지 궁금해졌다
> - from rest_framework_simplejwt import serializers as jwt_serializer
> - from rest_framework_simplejwt.tokens import RefreshToken

- applications

```python
from rest_framework import serializers
from rest_framework.fields import CreateOnlyDefault,CurrentUserDefault
from rest_framework.validators import UniqueTogetherValidator
from accounts.serializers import UserSerializer
from .models import Application

class ApplicationSerializer(serializers.ModelSerializer):
    applicant = UserSerializer(default=CreateOnlyDefault(CurrentUserDefault()))
    application_status = serializers.SerializerMethodField()
    
    class Meta:
        model = Application
        fields = ('id','team','applicant','reason','github_account','created_at','updated_at','application_status')
        read_only_fields = ('applicant',)
        validators = [
            UniqueTogetherValidator(
            	queryset=Application.objects.all(),
                fields=['team','applicant']
            )
        ]
        
    def get_application_status(self,application):
    	return application.get_status_display() # ??
```

> - import 구문에서 DRF 해당 문서는 살펴봐도 좋지 않을까??
>   - from rest_framework.fields import CreateOnlyDefault, CurrentUserDefault
>   - from rest_framework.validators import UniqueTogetherValidator
>   - serializers.SerializerMethodField()
>   - def get_application_status(self, application) ?
>     - application.get_status_display() ?
>   - UserSerializer(default=CreateOnlyDefault(CurrentUserDefault()))
>   - UniqueTogetherValidator

- teams

```python
from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework.fields import CreateOnlyDefault,CurrentUserDefault
from .models import Team,Tag,Comment
from applications.models import Application

User = get_user_model()

class TeammateSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = User
        fields = ('id','username','nickname','image')
    
class TagSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = Tag
        fields = ('name',)
    
class ChildCommentSerializer(serializers.ModelSerializer):
    author TeamateSerializer(default=CreateOnlyDefault(CurrentUserDefault()))
    
    class Meta:
        model = Comment
        fields = ['id','parent','team','author','body','created_at','updated_at']
    
class CommentSerializer(ChildCommentSerializer):
    
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.fields['child_comments_count'] = serializers.SerializerMethodField()
        self.fields['child_comments'] = self.__class__.__base__(many=True,read_only=True)
        
    def get_child_comments_count(self,obj):  
        return obj.child_comments.count()
    
class TeamListSerializer(serializers.ModelSerializer):
    leader = TeammateSerializer(default=CreateOnlyDefault(CurrentUserDefault()))
    tags = serializers.PrimaryKeyRelatedField(many=True,queryset=Tag.objects.all(),required=False)
    likes = TeammateSerializer(read_only=True,many=True)
    image = serializers.ImageField(required=False,use_url=True)
    parent_comments = serializers.SerializerMethodField()
    comments_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Team
        fields = ['id','tags','likes','like_count','leader','title','end_date','description','image','max_personnel','current_personnel','comments_count','parent_comments','created_at','updated_at']
        
    def get_parent_comments(self,obj):
        parent_comments = obj.comments.filter(parent=None)
        serializer = CommentSerializer(parent_comments,many=True)
        
    def get_comments_count(self,obj):    
        return obj.comments.count()
    
class TeamDetailSerializer(TeamListSerializer):
    
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.fields['is_applied'] = serializers.SerializerMethodField()
        self.fields['application_status'] = serializers.SerializerMethodField()
        self.fields['chat_url'] = serializers.SerializerMethodField()
        
    def get_is_applied(self,team):
        user = self.context['request'].user
        if user.is_anonymus or not user.applications.filter(team=team).exists():
            return False
        return True
        
    def get_application_status(self,team):
        user = self.context['request'].user
        if user.is_anonymous:
            return ""
        try:
            return team.applications.get(applicant=user).get_status_display()
        except Application.DoesNotExist:
            return ""
        
    def get_chat_url(self,team):  
        user = self.context['request'].user
        if user.is_anonymous:
            return ""
        if team.leader == user:
            return team.kakao_chat_url
        try:
            application = team.applications.get(applicant=user)
        except Application.DoesNotExist:
            return ""
        if application.status == 'approved':
            return team.kakao_chat_url
        return ""
    
class TeamListApplicationStatusSerializer(TeamListSerializer):
    
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.fields['application_status'] = serializers.SerializerMethodField()
        
    def get_application_status(self,team):    
        user = self.context['request'].user
        try:
            return team.applications.get(applicant=user).get_status_display()
        except Application.DoesNotExist:
            return Application.STATUS_DEFAULT_DISPLAY
```

> - serializers.SerializerMethodField()
>   - get_xxx() 함수로 반환? 뭔가 규칙이 있는데 흠

## views

- accounts

```python
from django.http import HttpResponseRedirect
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.viewset import ModelViewSet
from rest_framework.views import APIView
from rest_framework.decorators import action
from rest_framework.response import Response
from teams.models import Team
from teams.serializers import TeamListSerializer,TeamListApplicationStatusSerializer
from .serializers import SocialTokenObtainAccessSerializer,UserSerializer
from .permissions import IsSelfOrReadCreateOnly

User = get_user_model()

class SocialTokenObtainAccessView(TokenObtainPairView):
    serializer_class = SocialTokenObtainAccessSerializer
    
class GithubOauthRedirectView(APIView):
    
    def get(self,request,*args,**kwargs):
        response = HttpResponseRedirect(redirect_to='https://github.com/login/oauth/authorize?client_ida12345678')
        return response
    
class UserViewSet(ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsSelfOrReadCreateOnly]
    UNIQUE_FIELD = ['username','email','nickname']
    
    @action(methods=['post'],detail=False,url_path='check/duplication')
    def check_duplication(self,request,*args,**kwargs):
        queryset = self.get_queryset()
        data = request.data
        response_data = dict()
        for key,value in data.items():
            if key not in self.UNIQUE_FIELD:
                continue
            is_duplicated = queryset.filter(**{key:value}).exists()
            response_data[key] = is_duplicated
        return Response(response_data)    
        
    @action(methods=['get'],detail=False,url_path='self')
    def retrieve_request_user(self,request,*args,**kwargs):
        user = request.user
        serializer = self.get_serializer(user)
        return Response(serializer.data)
        
    @action(methods=['get'],detail=False,url_path='self/own/teams')
    def get_my_own_teams(self,request,*args,**kwargs):
        queryset = Team.objects.filter(leader=request.user)
        serializer = TeamListSerializer(queryset,many=True)
        return Response(serializer.data)
        
    @action(methods=['get'],detail=False,url_path='self/applied/teams')
    def get_my_applied_teams(self,request,*args,**kwargs):
        queryset = Team.objects.filter(applications__applicant=request.user)
        serializer = TeamListApplicationStatusSerializer(queryset,context={'request':request},many=True)
        return Response(serializer.data)
        
    	
```

> - from rest_framework.decorators

- applications

```python
from rest_framework.decorators import action
from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import Application
from .serializers import ApplicationSerializer
from .permissions import IsTeamLeader

class ApplicationViewSet(ModelViewSet):
    queryset = Application.objects.all()
    serializer_class = ApplicationSerializer
    permission_class = (IsAuthenticated,)
    
    def _change_application_status(self,request,status,pk=None):
        team = self.get_object()
        team.status = status
        team.save()
        serializer = self.get_serializer_class()
        return Response(serializer(team).data)
        
    @action(methods=['post'],detail=True,permission_classes=[IsAuthenticated,IsTeamLeader],url_path="refuse")
    def refuse_application(self,request,pk=None):
        return self._change_application_status(request,'refuse',pd)
    
    @action(methods=['post'],detail=True,permission_classes=[IsAuthenticated,IsTeamLeader],url_path='approve')
    def approve_application(self,request,pk=None):
        return self._change_application_status(request,'approved',pk)
```



- teams

```python
from django.db.models import Count
from django.contrib.auth import get_user_model
from rest_framework import filters,status,mixins
from rest_framework.viewsets import ModelViewSet,GenericViewSet
from rest_framework.permissions import IsAuthenticated,IsAuthenticatedOrReadOnly,AllowAny
from rest_framework.decorators import action
from rest_framework.response import Response
from applications.serializers import ApplicationSerializer
from .models import Team,Tag,Comment
from .serializer import TeamListSerializer,TeamDetailSerializer,TagSerializer,CommentSerializer
from .permissions import IsLeaderOrReadCreateOnly,IsUathor,IsLeader

User = get_user_model()

class TagViewSet(ModelViewSet):
    queryset = Tag.objects.all()
    serializer_class = TagSerializer
    permission_classes = (AllowAny,)
    filter_backends = (filters.SearchFilter,)
    search_fields = ('name',)
    
class CommentViewSet(mixins.CreateModelMixin,
                    mixins.UpdateModelMixin,
                    mixins.DestroyModelMixin,
                    GenericViewSet):
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    permission_classes = (IsAuthenticated,IsAuthor)
    
    def create(self,request,*args,**kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        team = serializer.instance.team
        comment_queryset = team.comments.filter(parent=None)
        data = self.get_serializer(comment_queryset,many=True).data
        return Response(data,status=status.HTTP_201_CREATED,headers=headers)
        
class TeamViewSet(ModelViewSet):
    queryset = Team.objects.all()
    serializer_class = TeamDetailSerializer
    permission_classes = (IsAuthenticatedOrReadOnly,IsLeaderOrReadCreateOnly)
    filter_backends = (filters.OrderingFilter,)
    ordering_fields = ('created_at','like_count')
    ordering = ('-created_at',)
    
    def get_serializer_class(self):
        if self.action == 'list':
            return TeamListSerializer
        return self.serializer_class
        
    def get_queryset(self):
        queryset = super().get_queryset()
        tags = self.request.query_params.getlist('tag')
        if tags:
            queryset = queryset.filter(tags__in=tags)
        return queryset    
        
    def filter_queryset(self,queryset):
        queryset = queryset.annotate(like_count=Count('likes'))
        return super().filter_queryset(queryset)
        
    def perform_create(self,serializer):
        serializer.save(leader=self.request.user)
        
    @action(methods=['get'],detail=False)
    def recent(self,request,*args,**kwargs):
        return self.list(request,*args,**kwargs)
        
    @action(methods=['post'],detail=True,name='Like Team')
    def like(self,request,pk=None):
        user = request.user
        team = self.get_object()
        
        if user in team.likes.all():
            team.likes.remove(user)
        else:
            team.likes.add(user)
        return Response(TeamListSerializer(team).data)    
        
    @action(methods=['get'],detail=True,url_path='comment')
    def list_comments(self,request,pk=None):
        team = self.get_object()
        parent_comments = team.comments.filter(parent=None)
        data = {
            'comments_count': team.comments.count(),
            'parent_comments': CommentSerializer(parent_comments,many=True).data
        }
        
    @action(methods=['get'],detail=True,url_path='application',permission_class=[IsAuthenticated,IsLeader])
    def list_applications(self,request,pk=None):
        team = self.get_object()
        applications = team.applications.all()
        return Response(ApplicationSerializer(applications,many=True).data)
```

> - queryset.annotate(like_count=Count('likes'))
> - filters.SearchFilter



## permissions

- accounts

```python
from rest_framework import permissions

class IsSelfOrReadCreateOnly(permissions.BasePermission):
    
    def has_object_permission(self,request,view,obj):
        if request.method in ('GET','HEAD','OPTIONS','POST'):
            return True
        elif request.method in ('PUT','PATCH','DELETE'):
            return obj == request.user
```



- applications

```python
from rest_framework import permissions

class TeamLeader(permissions.BasePermission):
    
    def has_object_permission(self,request,view,obj):
        return obj.team.leader == request.user
```



- teams
```python
from rest_framework import permissions

class IsLeaderOrReadCreateOnly(permissions.BasePermission):
    
    def has_object_permission(self,request,view,obj):
        if request.method in ('GET','HEAD','OPTIONS','POST'):
            return True
        elif request.method in ('PUT','PATCH','DELETE'):
            return obj.leader == request.user
    
class IsAuthor(permissions.BasePermission):
    
    def has_object_permission(self,request,view,obj):
        return obj.author == request.user
    
class IsLeader(permissions.BasePermission):
    
    def has_object_permission(self,request,view,obj):
        return obj.leader == request.user
    
```

## 기타등등

- accounts/utils

```python
import requests
import json
from django.conf import settings

GITHUB_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token/"
GITHUB_USER_URL = "https://api.github.com/user"

def get_github_access_token(code):
    headers = {
        'Accept': 'application/json; charset=utf-8',
    }
    body = {
        'client_id': settings.SOCIAL_AUTH_GITHUB_KEY,
        "client_secret": settings.SOCIAL_AUTH_GITHUB_SECRET,
        'code': code,
    }
    response = requests.post(GITHUB_ACCESS_TOKEN_URL,
                            data=body,headers=headers)
    return response.json()
    
def get_github_user_json(access_token):
    headers = {
        'Accept': 'application/json; charset=utf-8',
        'Authorization': 'token '+ access_token
    }
    response = requests.get(GITHUB_USER_URL,headers=headers)
    return response.json()
```



- config/backends

```python
from django.contrib.auth import get_user_model
from accounts.utils import get_github_access_token,get_github_user_json
from accounts.models import GithubProfile

GITHUB_USERNAME_PREFIX = 'github_'
User = get_user_model()

class GithubBackend:
    def authenticate(self,request,code=None,**kwargs):
        response = get_github_access_token(code)
        if 'error' in response:
            return
        access_token = response['access_token']
        github_user_json = get_github_user_json(access_token)
        
        profile_id = github_user_json['id']
        login = github_user_json['login']
        defaults = {
            'avatar': github_user_json['avatar_url'],
            'email': github_user_json['email'],
            'login': github_user_json['login']
        }
        profile,is_new = GithubProfile.objects.update_or_create(id=profle_id,defaults=defaults)
        if is_new:
            user = User.objects._create_user(username=GITHUB_USERNAME_PREFIX+login,email=None,password=None,profile=profile)
        else:
            user = profile.user
            
        return user    
```

> - GithubProfile.objects.update_or_create
>   - defaults
>   - profile,is_new ??


