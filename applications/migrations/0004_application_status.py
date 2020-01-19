# Generated by Django 2.2.6 on 2020-01-18 08:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('applications', '0003_auto_20200102_1824'),
    ]

    operations = [
        migrations.AddField(
            model_name='application',
            name='status',
            field=models.CharField(choices=[('waiting', '대기중'), ('expiry', '만료됨'), ('approved', '승인됨'), ('refuse', '거절됨')], default='waiting', max_length=10, verbose_name='상태'),
        ),
    ]