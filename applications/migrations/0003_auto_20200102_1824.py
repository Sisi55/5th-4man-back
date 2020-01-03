# Generated by Django 2.2.6 on 2020-01-02 09:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('applications', '0002_auto_20200102_1814'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='application',
            unique_together=set(),
        ),
        migrations.AddConstraint(
            model_name='application',
            constraint=models.UniqueConstraint(fields=('team', 'applicant'), name='unique_application'),
        ),
    ]