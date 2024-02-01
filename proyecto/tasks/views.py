import re
from django.shortcuts import render, redirect ,get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.contrib.auth.decorators import login_required
from .models import task
from .forms import taskform
from django.utils import timezone
from django.contrib.auth.decorators import login_required

# Create your views here.
def home(request):
    return render(request, 'home.html')


def is_valid_password(password):
    # La contraseña debe tener al menos 8 caracteres
    # Debe contener al menos una letra mayúscula, una letra minúscula y un carácter especial
    regex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
    return bool(regex.match(password))

def signup(request):
    if request.method == 'GET':
        return render(request, 'signup.html', {'form': UserCreationForm})
    else:
        password1 = request.POST['password1']
        password2 = request.POST['password2']

        if password1 == password2 and is_valid_password(password1):
            try:
                user = User.objects.create_user(
                    username=request.POST['username'], password=password1)
                user.save()
                login(request, user)
                return redirect('tasks')
            except IntegrityError:
                return render(request, 'signup.html', {'form': UserCreationForm, 'error': 'El usuario ya existe'})

        return render(request, 'signup.html', {'form': UserCreationForm, 'error': 'La longitud de la contraseña es inválida o las contraseñas no coinciden o no cumplen con los requisitos'})


@login_required
def tasks(request):
    tasks = task.objects.filter(user=request.user, datecompleted__isnull=True)
    return render(request, 'tasks.html', {"tasks": tasks})



@login_required
def tasks_completed(request):
    tasks = task.objects.filter(user=request.user, datecompleted__isnull=False).order_by('-datecompleted')
    return render(request, 'tasks.html', {"tasks": tasks})





@login_required
def create_task(request):
    if request.method == "GET":
        return render(request, 'create_task.html', {"form": taskform})
    else:
        try:
            form = taskform(request.POST)
            new_task = form.save(commit=False)
            new_task.user = request.user
            new_task.save()
            return redirect('tasks')
        except ValueError:
            return render(request, 'create_task.html', {"form": taskform, "error": "Error creating task."})





@login_required
def task_detail(request, task_id):
    if request.method == 'GET':
        Task = get_object_or_404(task, pk=task_id, user=request.user)
        Form = taskform(instance=Task)
        return render(request, 'task_detail.html', {"task": Task, "form": Form})
    else:
        try:
            Task = get_object_or_404(task, pk=task_id, user=request.user)
            form = taskform(request.POST, instance=Task)
            form.save()
            return redirect('tasks')
        except ValueError:
            return render(request, 'task_detail.html', {'task': Task, 'form': form, 'error': 'Error actualizando task.'})
    
    
    
  
  
  
@login_required  
def complete_task(request, task_id):
    Task = get_object_or_404(task, pk=task_id, user=request.user)
    if request.method == 'POST':
        Task.datecompleted = timezone.now()
        Task.save()
        return redirect('tasks')





@login_required
def delete_task(request, task_id):
    Task = get_object_or_404(task, pk=task_id, user=request.user)
    if request.method == 'POST':
        Task.delete()
        return redirect('tasks')    
    
    
  
    
    
@login_required
def desconectar(request):
    logout(request)
    return redirect('home')


def iniciarSesion(request):
    if request.method == 'GET':
        return render(request, 'iniciarSesion.html', {'form': AuthenticationForm})
    else:
        user = authenticate(
            request, username=request.POST['username'], password=request.POST['password'])
        if user is None:
            return render(request, 'iniciarSesion.html', {'form': AuthenticationForm, 'error': 'el usuario o la contraseña  es incorrecto'})
        else:
            login(request, user)
            return redirect(tasks)